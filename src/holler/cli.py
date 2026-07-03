import argparse
import asyncio
import getpass
import sys

from holler.client import Client
from holler.errors import AuthenticationError, PeerUnreachableError
from holler.peer import DEFAULT_SIGNALING_URL, DEFAULT_STUN_URL, build_ice_servers
from holler.ui import TerminalUI


def main():
    parser = argparse.ArgumentParser(description="Peer-to-peer encrypted terminal chat")
    parser.add_argument("username")
    parser.add_argument(
        "password",
        nargs="?",
        help="shared room password (omit to be prompted securely — "
        "passing it as an argument exposes it to `ps` and shell history)",
    )
    parser.add_argument("--join", "-j", metavar="ROOM_ID", help="room ID to connect to")
    parser.add_argument(
        "--signaling",
        metavar="URL",
        default=DEFAULT_SIGNALING_URL,
        help=f"PeerJS-compatible signaling server websocket URL (default: {DEFAULT_SIGNALING_URL})",
    )
    parser.add_argument(
        "--stun",
        metavar="URL",
        default=DEFAULT_STUN_URL,
        help=f"STUN server URL (default: {DEFAULT_STUN_URL})",
    )
    parser.add_argument(
        "--turn", metavar="URL", help="optional TURN relay URL, e.g. turn:host:3478"
    )
    parser.add_argument("--turn-user", metavar="USER", help="TURN username")
    parser.add_argument("--turn-pass", metavar="PASS", help="TURN password")

    args = parser.parse_args()
    password = args.password
    if password is None:
        password = getpass.getpass("Room password: ")
    if not password:
        sys.exit("error: a password is required")

    client = Client(
        username=args.username,
        password=password,
        join_id=args.join,
        signaling_url=args.signaling,
        ice_servers=build_ice_servers(args.stun, args.turn, args.turn_user, args.turn_pass),
    )
    try:
        asyncio.run(TerminalUI(client).run())
    except KeyboardInterrupt:
        pass
    except AuthenticationError:
        sys.exit("error: authentication failed — check that everyone uses the same password")
    except PeerUnreachableError:
        sys.exit("error: could not reach the room — check the room ID and try again")
    except ConnectionError as exc:
        sys.exit(f"error: signaling server connection failed ({exc})")


if __name__ == "__main__":
    main()
