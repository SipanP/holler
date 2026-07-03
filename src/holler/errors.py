"""Exception types shared across holler modules."""


class HollerError(Exception):
    """Base class for all holler errors."""


class ProtocolError(HollerError):
    """A peer sent a message that violates the holler protocol."""


class AuthenticationError(HollerError):
    """The pairwise handshake failed — almost always a password mismatch."""


class PeerUnreachableError(HollerError):
    """A peer (or room ID) could not be reached through the signaling server."""
