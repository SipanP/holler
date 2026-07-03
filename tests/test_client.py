import asyncio

import pytest

import holler.client as client_mod
from holler.errors import AuthenticationError, PeerUnreachableError
from tests.conftest import eventually


def chats(events, text=None):
    found = [p for k, p in events if k == "chat"]
    if text is not None:
        found = [p for p in found if p["text"] == text]
    return found


def infos(events):
    return [p["text"] for k, p in events if k == "info"]


async def start_room(make_client, *names, password="pw"):
    """Starts a host plus joiners and waits for the full mesh to form."""
    host, host_events = make_client(names[0], password)
    await host.start()
    room = host.room_id
    clients = [(host, host_events)]
    for name in names[1:]:
        joiner, joiner_events = make_client(name, password, join=room)
        await joiner.start()
        clients.append((joiner, joiner_events))
    for client, _ in clients:
        assert await eventually(lambda c=client: len(c.online) == len(names))
    return room, clients


async def test_host_creates_room_and_joiner_connects(make_client, hub):
    host, host_events = make_client("alice")
    await host.start()
    assert host.room_id in hub.owners
    assert ("room", {"room_id": host.room_id}) in host_events

    joiner, _ = make_client("bob", join=host.room_id)
    await joiner.start()
    assert await eventually(lambda: sorted(host.online) == ["alice", "bob"])
    assert await eventually(lambda: sorted(joiner.online) == ["alice", "bob"])
    assert any("bob joined" in t for t in infos(host_events))


async def test_wrong_password_fails_loudly(make_client):
    host, host_events = make_client("alice", password="right")
    await host.start()
    joiner, _ = make_client("bob", password="wrong", join=host.room_id)
    with pytest.raises(AuthenticationError):
        await joiner.start()
    assert await eventually(
        lambda: any(k == "error" and "authentication" in p["text"] for k, p in host_events)
    )
    assert host.online == ["alice"]


async def test_join_unknown_room_fails_fast(make_client):
    joiner, _ = make_client("bob", join="nosuchroom123")
    with pytest.raises(PeerUnreachableError):
        await joiner.start()


async def test_three_peer_full_mesh_via_roster(make_client):
    _, clients = await start_room(make_client, "alice", "bob", "carol")
    for client, _ in clients:
        assert sorted(client.online) == ["alice", "bob", "carol"]


async def test_chat_reaches_all_peers_exactly_once(make_client):
    _, clients = await start_room(make_client, "alice", "bob", "carol")
    (_, _), (bob, _), _ = clients
    await bob.send_chat("hello everyone")
    for client, events in clients:
        assert await eventually(lambda e=events: chats(e, "hello everyone"))
    await asyncio.sleep(0.3)  # allow any duplicate delivery to surface
    for client, events in clients:
        received = chats(events, "hello everyone")
        assert len(received) == 1
        assert received[0]["username"] == "bob"


async def test_gossip_relays_around_dead_link(make_client, hub):
    _, clients = await start_room(make_client, "alice", "bob", "carol")
    # Disable staleness reconnection so the dead link stays dead.
    for client, _ in clients:
        client._stale_after = 60.0
    (alice, alice_events), (bob, _), _ = clients
    hub.sever(alice._peer, bob._peer)

    await bob.send_chat("via relay")
    assert await eventually(lambda: chats(alice_events, "via relay"))
    await asyncio.sleep(0.3)
    received = chats(alice_events, "via relay")
    assert len(received) == 1
    assert received[0]["username"] == "bob"


async def test_ttl_stops_forwarding(make_client, hub, monkeypatch):
    _, clients = await start_room(make_client, "alice", "bob", "carol")
    for client, _ in clients:
        client._stale_after = 60.0
    (alice, alice_events), (bob, _), (_, carol_events) = clients
    hub.sever(alice._peer, bob._peer)

    monkeypatch.setattr(client_mod, "GOSSIP_TTL", 1)
    await bob.send_chat("dies at first hop")
    assert await eventually(lambda: chats(carol_events, "dies at first hop"))
    await asyncio.sleep(0.3)
    assert not chats(alice_events, "dies at first hop")


async def test_lamport_ordering_is_consistent(make_client):
    _, clients = await start_room(make_client, "alice", "bob")
    (alice, _), (bob, bob_events) = clients
    await alice.send_chat("first")
    assert await eventually(lambda: chats(bob_events, "first"))
    await bob.send_chat("second")
    assert await eventually(lambda: len(alice.log) == 2)

    for client, _ in clients:
        keys = [key for key, _ in client.log]
        assert keys == sorted(keys)
        texts = [entry["text"] for _, entry in client.log]
        assert texts == ["first", "second"]


async def test_leave_announces_and_rotates_sender_key(make_client):
    _, clients = await start_room(make_client, "alice", "bob", "carol")
    (alice, alice_events), (bob, _), (carol, carol_events) = clients
    alice_id = alice._peer.peer_id
    old_key = alice._sender_key

    await bob.stop()
    assert await eventually(lambda: any("bob left" in t for t in infos(alice_events)))
    assert await eventually(lambda: sorted(alice.online) == ["alice", "carol"])
    assert await eventually(lambda: alice._sender_key != old_key)
    # Carol received the rotated key and can still read Alice's messages.
    assert await eventually(
        lambda: carol._sender_keys.get(alice_id, [None])[0] == alice._sender_key
    )
    await alice.send_chat("after rotation")
    assert await eventually(lambda: chats(carol_events, "after rotation"))


async def test_room_takeover_and_rejoin(make_client, hub):
    room, clients = await start_room(make_client, "alice", "bob", "carol")
    # The room settles on the peer with the lowest real ID, whoever created it.
    holder = min((c for c, _ in clients), key=lambda c: c._peer.peer_id)
    assert await eventually(lambda: hub.owners.get(room) is holder._peer)

    await holder.stop()
    survivors = [c for c, _ in clients if c is not holder]
    expected_holder = min(survivors, key=lambda c: c._peer.peer_id)
    assert await eventually(lambda: hub.owners.get(room) is expected_holder._peer, timeout=10.0)

    dave, _ = make_client("dave", join=room)
    await dave.start()
    survivor_names = sorted(c.username for c in survivors)
    assert await eventually(lambda: sorted(dave.online) == survivor_names + ["dave"])
    for survivor in survivors:
        assert await eventually(lambda s=survivor: "dave" in s.online)


async def test_reconnects_after_silent_link_death(make_client, hub):
    _, clients = await start_room(make_client, "alice", "bob")
    (alice, alice_events), (bob, bob_events) = clients
    hub.sever(alice._peer, bob._peer)

    assert await eventually(
        lambda: any("reconnected" in t for t in infos(alice_events) + infos(bob_events)),
        timeout=10.0,
    )
    assert await eventually(lambda: sorted(alice.online) == ["alice", "bob"])
    assert await eventually(lambda: sorted(bob.online) == ["alice", "bob"])

    await alice.send_chat("still here")
    assert await eventually(lambda: chats(bob_events, "still here"))


async def test_unreachable_peer_is_removed_after_reconnect_fails(make_client, hub):
    _, clients = await start_room(make_client, "alice", "bob")
    (alice, alice_events), (bob, _) = clients
    # Bob vanishes without a leave: registration gone, link silently dead.
    await bob._peer.close()
    bob.running = False
    hub.sever(alice._peer, bob._peer)

    assert await eventually(lambda: any("bob left" in t for t in infos(alice_events)), timeout=10.0)
    assert alice.online == ["alice"]


async def test_typing_indicator_roundtrip(make_client):
    _, clients = await start_room(make_client, "alice", "bob")
    (alice, _), (_, bob_events) = clients
    alice.notify_typing()
    assert await eventually(
        lambda: any(k == "typing" and p["users"] == ["alice"] for k, p in bob_events)
    )
    # Expires again after the typing window passes.
    assert await eventually(lambda: any(k == "typing" and p["users"] == [] for k, p in bob_events))
