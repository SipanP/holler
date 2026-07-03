"""WebRTC peer connection management backed by PeerJS signaling."""

import asyncio
import contextlib
import json
import logging
from typing import Any, Callable, Optional

import websockets
from aiortc import RTCConfiguration, RTCIceServer, RTCPeerConnection, RTCSessionDescription

from holler.crypto import rand_id
from holler.errors import PeerUnreachableError

logger = logging.getLogger(__name__)

DEFAULT_SIGNALING_URL = "wss://0.peerjs.com/peerjs"
DEFAULT_STUN_URL = "stun:stun.l.google.com:19302"
PEERJS_KEY = "peerjs"

# The PeerJS server expires clients whose last heartbeat is older than its
# alive timeout (60 s by default), so the client must ping proactively.
HEARTBEAT_INTERVAL = 5.0
RECONNECT_DELAYS = (1, 2, 4, 8, 16, 30, 30, 30)


def build_ice_servers(
    stun_url: str = DEFAULT_STUN_URL,
    turn_url: Optional[str] = None,
    turn_username: Optional[str] = None,
    turn_password: Optional[str] = None,
) -> "list[RTCIceServer]":
    """Builds the ICE server list from CLI-style options.

    Args:
        stun_url: STUN server URL for NAT hole punching.
        turn_url: Optional TURN relay URL (``turn:host:port``) used when hole
            punching fails. TURN-over-UDP only; TCP relays are not configured
            because holler peers never accept inbound TCP.
        turn_username: TURN credential username.
        turn_password: TURN credential password.
    """
    servers = [RTCIceServer(urls=stun_url)]
    if turn_url:
        servers.append(
            RTCIceServer(urls=turn_url, username=turn_username, credential=turn_password)
        )
    return servers


async def _wait_for_ice(pc: RTCPeerConnection):
    if pc.iceGatheringState == "complete":
        return
    done = asyncio.Event()

    @pc.on("icegatheringstatechange")
    def on_state_change():
        if pc.iceGatheringState == "complete":
            done.set()

    await done.wait()


class PeerConnection:
    """Manages multiple WebRTC DataChannel connections via PeerJS signaling.

    One instance holds a single PeerJS websocket (the peer's own ID) plus an
    optional alias websocket (the room ID). Each websocket is supervised: the
    client sends protocol heartbeats and transparently reconnects with
    exponential backoff if the socket drops, re-registering the same ID.

    Attributes:
        peer_id: The ephemeral ID registered with PeerJS on start.
        on_message: Callback fired when a message arrives on any channel.
            Signature: ``(peer_id: str, data: str) -> None``
        on_peer_connected: Callback fired when a DataChannel opens.
            Signature: ``(peer_id: str) -> None``
        on_peer_disconnected: Callback fired exactly once when an open
            DataChannel goes away. Signature: ``(peer_id: str) -> None``
        on_alias_lost: Callback fired when an alias registration could not be
            restored after a signaling reconnect. Signature: ``(alias: str) -> None``
        on_signaling_lost: Callback fired when the peer's own registration is
            permanently lost. Existing DataChannels keep working, but no new
            peers can dial in. Signature: ``() -> None``
    """

    def __init__(
        self,
        signaling_url: str = DEFAULT_SIGNALING_URL,
        ice_servers: "Optional[list[RTCIceServer]]" = None,
    ):
        self.peer_id = rand_id()
        self._url = signaling_url
        self._ice_config = RTCConfiguration(iceServers=ice_servers or build_ice_servers())

        self._websockets: dict[str, Any] = {}
        self._supervisors: dict[str, asyncio.Task] = {}
        self._pcs: dict[str, RTCPeerConnection] = {}
        self._channels: dict = {}
        self._pending: dict[str, asyncio.Future] = {}
        self._closing = False

        self.on_message: Optional[Callable[[str, str], None]] = None
        self.on_peer_connected: Optional[Callable[[str], None]] = None
        self.on_peer_disconnected: Optional[Callable[[str], None]] = None
        self.on_alias_lost: Optional[Callable[[str], None]] = None
        self.on_signaling_lost: Optional[Callable[[], None]] = None

    @property
    def connected_peers(self) -> "list[str]":
        """Returns the peer IDs of all currently open DataChannels."""
        return list(self._channels.keys())

    async def start(self):
        """Registers ``peer_id`` with PeerJS and starts the supervised signaling loop."""
        await self._register(self.peer_id)

    async def register_alias(self, alias_id: str):
        """Registers an additional ID with PeerJS (used for the room ID).

        Args:
            alias_id: The ID to register. Incoming offers on this ID are
                handled identically to offers on ``peer_id``.

        Raises:
            ConnectionError: If PeerJS rejects the registration (e.g. ID taken).
        """
        await self._register(alias_id)

    async def unregister_alias(self, alias_id: str):
        """Closes the PeerJS websocket for a previously registered alias.

        Args:
            alias_id: The alias ID to deregister.
        """
        await self._teardown_registration(alias_id)

    async def connect_to(self, target_peer_id: str, timeout: float = 30.0):
        """Initiates a WebRTC connection to another peer and waits for the
        DataChannel to open.

        Args:
            target_peer_id: The PeerJS ID of the remote peer.
            timeout: Seconds to wait for the channel to open.

        Raises:
            PeerUnreachableError: If the peer does not exist, is gone, or did
                not answer within the timeout.
            ConnectionError: If our own signaling socket is unavailable.
        """
        if target_peer_id in self._channels:
            return
        fut: asyncio.Future = asyncio.get_running_loop().create_future()
        self._pending[target_peer_id] = fut
        try:
            await self._send_offer(target_peer_id)
            await asyncio.wait_for(fut, timeout)
        except asyncio.TimeoutError:
            raise PeerUnreachableError(f"{target_peer_id} did not answer") from None
        finally:
            self._pending.pop(target_peer_id, None)
            if target_peer_id not in self._channels:
                pc = self._pcs.pop(target_peer_id, None)
                if pc:
                    asyncio.create_task(pc.close())

    async def send_to(self, peer_id: str, data: str):
        """Sends a message to a specific connected peer.

        Args:
            peer_id: Recipient's peer ID.
            data: Message string to send.
        """
        ch = self._channels.get(peer_id)
        if ch and ch.readyState == "open":
            try:
                ch.send(data)
            except Exception:
                logger.debug("send to %s failed", peer_id, exc_info=True)

    async def broadcast(self, data: str):
        """Sends a message to every currently open DataChannel.

        Args:
            data: Message string to send.
        """
        for peer_id in list(self._channels.keys()):
            await self.send_to(peer_id, data)

    async def drop(self, peer_id: str):
        """Tears down the connection to one peer (used for dead-link recovery)."""
        self._channel_gone(peer_id)

    async def close(self):
        """Cancels all signaling tasks, closes all websockets and RTCPeerConnections."""
        self._closing = True
        for peer_id in list(self._supervisors.keys()):
            await self._teardown_registration(peer_id)
        for pc in list(self._pcs.values()):
            await pc.close()
        self._pcs.clear()
        self._channels.clear()

    # ── signaling lifecycle ──────────────────────────────────────────────────

    async def _register(self, peer_id: str):
        ws = await self._connect_ws(peer_id)
        self._websockets[peer_id] = ws
        self._supervisors[peer_id] = asyncio.create_task(self._supervise(peer_id, ws))

    async def _connect_ws(self, peer_id: str):
        url = f"{self._url}?key={PEERJS_KEY}&id={peer_id}&token={rand_id(16)}"
        ws = await websockets.connect(url)
        try:
            msg = json.loads(await asyncio.wait_for(ws.recv(), timeout=10))
        except Exception:
            await ws.close()
            raise ConnectionError("PeerJS registration failed: no response") from None
        if msg.get("type") != "OPEN":
            await ws.close()
            raise ConnectionError(f"PeerJS registration failed: {msg}")
        return ws

    async def _teardown_registration(self, peer_id: str):
        task = self._supervisors.pop(peer_id, None)
        if task:
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task
        ws = self._websockets.pop(peer_id, None)
        if ws:
            with contextlib.suppress(Exception):
                await ws.close()

    async def _supervise(self, peer_id: str, ws: Any):
        """Runs the signaling loop for one registration, reconnecting on drops."""
        while not self._closing:
            heartbeat = asyncio.create_task(self._heartbeat(ws))
            try:
                await self._signaling_loop(ws)
            except asyncio.CancelledError:
                heartbeat.cancel()
                raise
            except Exception:
                logger.debug("signaling loop for %s errored", peer_id, exc_info=True)
            finally:
                heartbeat.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await heartbeat
            self._websockets.pop(peer_id, None)
            if self._closing:
                return

            ws = await self._reconnect_ws(peer_id)
            if ws is None:
                # Deregister ourselves without cancelling our own task.
                self._supervisors.pop(peer_id, None)
                if peer_id == self.peer_id:
                    if self.on_signaling_lost:
                        self.on_signaling_lost()
                elif self.on_alias_lost:
                    self.on_alias_lost(peer_id)
                return
            self._websockets[peer_id] = ws

    async def _reconnect_ws(self, peer_id: str):
        for delay in RECONNECT_DELAYS:
            await asyncio.sleep(delay)
            if self._closing:
                return None
            try:
                return await self._connect_ws(peer_id)
            except Exception:
                continue
        return None

    async def _heartbeat(self, ws: Any):
        while True:
            await asyncio.sleep(HEARTBEAT_INTERVAL)
            await ws.send(json.dumps({"type": "HEARTBEAT"}))

    async def _signaling_loop(self, ws: Any):
        try:
            async for raw in ws:
                msg = json.loads(raw)
                t = msg.get("type")

                if t == "OFFER":
                    await self._handle_offer(ws, msg["src"], msg["payload"])
                elif t == "ANSWER":
                    await self._handle_answer(msg["src"], msg["payload"])
                elif t in ("LEAVE", "EXPIRE"):
                    self._fail_pending(msg.get("src"))
        except websockets.ConnectionClosed:
            pass

    def _fail_pending(self, src: Optional[str]):
        """Fails a pending dial fast when signaling reports the target is gone."""
        if not src:
            return
        fut = self._pending.get(src)
        if fut and not fut.done():
            fut.set_exception(PeerUnreachableError(f"{src} is not reachable"))

    # ── WebRTC handshake ─────────────────────────────────────────────────────

    async def _send_offer(self, target: str):
        ws = self._websockets.get(self.peer_id)
        if ws is None:
            raise ConnectionError("signaling connection unavailable")
        pc = RTCPeerConnection(configuration=self._ice_config)
        self._pcs[target] = pc
        ch = pc.createDataChannel("chat")
        self._bind_channel(target, ch)
        self._bind_pc(target, pc)

        offer = await pc.createOffer()
        await pc.setLocalDescription(offer)
        await _wait_for_ice(pc)

        await ws.send(
            json.dumps(
                {
                    "type": "OFFER",
                    "dst": target,
                    "payload": {"sdp": pc.localDescription.sdp, "type": "offer"},
                }
            )
        )

    async def _handle_offer(self, ws: Any, src: str, payload: dict):
        if src in self._pending:
            # Glare: both sides dialed simultaneously. Deterministic tie-break —
            # the lexicographically lower peer ID stays the offerer.
            if self.peer_id < src:
                return
            old = self._pcs.pop(src, None)
            if old:
                await old.close()
        elif src in self._channels:
            # The remote considers the old link dead and is re-dialing; drop
            # our side and accept the fresh connection.
            old_pc = self._pcs.pop(src, None)
            self._channel_gone(src)
            if old_pc:
                await old_pc.close()

        pc = RTCPeerConnection(configuration=self._ice_config)
        self._pcs[src] = pc
        self._bind_pc(src, pc)

        @pc.on("datachannel")
        def on_datachannel(ch):
            self._bind_channel(src, ch)

        await pc.setRemoteDescription(RTCSessionDescription(sdp=payload["sdp"], type="offer"))
        answer = await pc.createAnswer()
        await pc.setLocalDescription(answer)
        await _wait_for_ice(pc)

        await ws.send(
            json.dumps(
                {
                    "type": "ANSWER",
                    "dst": src,
                    "payload": {"sdp": pc.localDescription.sdp, "type": "answer"},
                }
            )
        )

    async def _handle_answer(self, src: str, payload: dict):
        pc = self._pcs.get(src)
        if pc and pc.signalingState == "have-local-offer":
            await pc.setRemoteDescription(RTCSessionDescription(sdp=payload["sdp"], type="answer"))

    def _bind_pc(self, peer_id: str, pc: RTCPeerConnection):
        @pc.on("connectionstatechange")
        def on_state_change():
            if pc.connectionState in ("failed", "closed") and self._pcs.get(peer_id) is pc:
                self._channel_gone(peer_id)

    def _bind_channel(self, peer_id: str, ch):
        def on_open():
            self._channels[peer_id] = ch
            fut = self._pending.get(peer_id)
            if fut and not fut.done():
                fut.set_result(None)
            if self.on_peer_connected:
                self.on_peer_connected(peer_id)

        ch.on("open", on_open)

        @ch.on("message")
        def on_message(data):
            if self.on_message and isinstance(data, str):
                self.on_message(peer_id, data)

        @ch.on("close")
        def on_close():
            if self._channels.get(peer_id) is ch:
                self._channel_gone(peer_id)

        # Remotely-created channels are already open when aiortc emits the
        # "datachannel" event, so the "open" event will never fire for them.
        if ch.readyState == "open":
            on_open()

    def _channel_gone(self, peer_id: str):
        """Removes a peer's channel + pc, firing ``on_peer_disconnected`` once."""
        had_channel = self._channels.pop(peer_id, None) is not None
        pc = self._pcs.pop(peer_id, None)
        if pc:
            asyncio.create_task(pc.close())
        if had_channel and self.on_peer_disconnected:
            self.on_peer_disconnected(peer_id)
