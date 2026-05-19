"""Error mapping for the GoodNet C ABI result codes.

``Status`` mirrors the ``gn_result_t`` enum from ``sdk/types.h`` —
zero is success, negative values are failures. ``Error`` is the
Python exception class the high-level wrapper raises on a non-zero
result; ``Error.from_code(rc)`` builds an exception that carries the
``Status`` member and the kernel-side message text.
"""
from __future__ import annotations

from enum import IntEnum


class Status(IntEnum):
    """``gn_result_t`` codes — kept in lockstep with sdk/types.h."""

    OK = 0
    ERR_NULL_ARG = -1
    ERR_OUT_OF_MEMORY = -2
    ERR_INVALID_ENVELOPE = -3
    ERR_UNKNOWN_RECEIVER = -4
    ERR_PAYLOAD_TOO_LARGE = -5
    ERR_DEFRAME_INCOMPLETE = -6
    ERR_DEFRAME_CORRUPT = -7
    ERR_NOT_IMPLEMENTED = -8
    ERR_VERSION_MISMATCH = -9
    ERR_LIMIT_REACHED = -10
    ERR_INVALID_STATE = -11
    ERR_INTEGRITY_FAILED = -12
    ERR_INTERNAL = -13
    ERR_NOT_FOUND = -14
    ERR_OUT_OF_RANGE = -15
    ERR_FRAME_TOO_LARGE = -16
    ERR_WIRE_DECODE = -17

    @classmethod
    def from_code(cls, code: int) -> "Status":
        """Return the matching status; unknown values map to ``ERR_INTERNAL``.

        The kernel may add new result codes in minor releases; per the
        SDK contract consumers default-handle unknown values rather
        than enumerate. The wrapper surfaces the raw integer through
        ``Error.code`` so callers can still inspect the exact value.
        """
        try:
            return cls(code)
        except ValueError:
            return cls.ERR_INTERNAL


# Stable strings for each enumerator; matches ``gn_strerror`` in
# sdk/types.h. Kept in Python so the binding does not need to call
# back into the SDK for every error message.
_MESSAGES: dict[Status, str] = {
    Status.OK: "ok",
    Status.ERR_NULL_ARG: "null argument where required",
    Status.ERR_OUT_OF_MEMORY: "out of memory",
    Status.ERR_INVALID_ENVELOPE: (
        "invalid envelope (zero sender_pk, zero msg_id, or non-zero _reserved)"
    ),
    Status.ERR_UNKNOWN_RECEIVER: (
        "unknown receiver public key (no local identity, no relay)"
    ),
    Status.ERR_PAYLOAD_TOO_LARGE: (
        "payload exceeds the configured max_payload_size"
    ),
    Status.ERR_DEFRAME_INCOMPLETE: "partial frame buffered for retry",
    Status.ERR_DEFRAME_CORRUPT: (
        "frame deframe failed (magic mismatch, bad version, or length overflow)"
    ),
    Status.ERR_NOT_IMPLEMENTED: "not implemented",
    Status.ERR_VERSION_MISMATCH: (
        "version mismatch (plugin SDK major != kernel SDK major)"
    ),
    Status.ERR_LIMIT_REACHED: "limit reached",
    Status.ERR_INVALID_STATE: (
        "invalid state (operation illegal in current phase)"
    ),
    Status.ERR_INTEGRITY_FAILED: (
        "integrity check failed (manifest mismatch, tampered binary, "
        "or strict-mode manifest absent)"
    ),
    Status.ERR_INTERNAL: (
        "internal kernel error (exception crossed a C ABI boundary)"
    ),
    Status.ERR_NOT_FOUND: "not found",
    Status.ERR_OUT_OF_RANGE: (
        "value outside the contract's permitted range"
    ),
    Status.ERR_FRAME_TOO_LARGE: "wire frame exceeds kMaxFrameBytes ceiling",
    Status.ERR_WIRE_DECODE: (
        "wire-format decode failed (CBOR type mismatch, EOF, or bad tag)"
    ),
}


def strerror(code: int) -> str:
    """Translate a raw result code into the SDK's stable description."""
    status = Status.from_code(code)
    return _MESSAGES.get(status, "unknown gn_result_t")


class Error(Exception):
    """Raised when a ``gn_*`` entry returns a non-zero result code.

    Attributes:
        code: the raw ``gn_result_t`` integer.
        status: the matching ``Status`` enumerator (best-effort for
            unknown codes — see ``Status.from_code``).
        context: optional caller-supplied text identifying the call
            site (``"gn_core_init"`` etc).
    """

    def __init__(self, code: int, context: str | None = None) -> None:
        self.code = int(code)
        self.status = Status.from_code(self.code)
        self.context = context
        suffix = f" ({context})" if context else ""
        super().__init__(f"{strerror(self.code)} [code={self.code}]{suffix}")

    @classmethod
    def from_code(cls, code: int, context: str | None = None) -> "Error":
        return cls(code, context)


def check(code: int, context: str | None = None) -> None:
    """Raise ``Error`` when ``code`` is non-zero; no-op on ``GN_OK``."""
    if code != Status.OK:
        raise Error(code, context)


__all__ = ["Error", "Status", "check", "strerror"]
