import argparse

from holler.client import Client


def main():
    parser = argparse.ArgumentParser(description="Peer-to-peer encrypted terminal chat")
    parser.add_argument("username")
    parser.add_argument("password")
    parser.add_argument("--join", "-j", metavar="PEER_ID", help="Peer ID to connect to")

    args = parser.parse_args()
    Client(username=args.username, password=args.password, join_id=args.join).run()


if __name__ == "__main__":
    main()
