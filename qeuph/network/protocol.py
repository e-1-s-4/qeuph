"""
Wire protocol: length-prefixed frames with magic, command and checksum.

Frame layout (all little-endian):

    magic    4 bytes   b"QUH!" (network-specific)
    command  12 bytes  ASCII, NUL padded
    length   4 bytes   payload length
    checksum 4 bytes   first 4 bytes of double-SHA3-512(payload)
    payload  `length` bytes

Payloads are JSON documents (simple, debuggable; binary data hex-encoded).
Commands: version, verack, getheaders, headers, getblocks, block, inv,
getdata, notfound, tx, mempool, ping, pong, getaddr, addr.

Every network has its own magic bytes, so a testnet peer dialing a mainnet
port is rejected by the frame reader instead of being parsed.

Ported from QRL's socket/protocol.py framing philosophy (QRL used protobuf
over twisted; Qeuph uses JSON over asyncio to keep the dependency set at
stdlib-only).
"""
from __future__ import annotations

import json
import struct
from typing import Optional, Tuple

from qeuph import constants as C
from qeuph.crypto.address import dhash

MAX_PAYLOAD = 8 * 1024 * 1024

COMMANDS = {
    "version", "verack", "getheaders", "headers", "getblocks", "block",
    "inv", "getdata", "notfound", "tx", "mempool", "ping", "pong",
    "getaddr", "addr",
}


def encode_frame(command: str, payload: dict, magic: bytes = C.MAGIC_BYTES) -> bytes:
    if command not in COMMANDS:
        raise ValueError(f"unknown command {command!r}")
    raw = json.dumps(payload, separators=(",", ":")).encode()
    if len(raw) > MAX_PAYLOAD:
        raise ValueError("payload too large")
    cmd = command.encode().ljust(12, b"\x00")
    checksum = dhash(raw)[:4]
    return magic + cmd + struct.pack("<I", len(raw)) + checksum + raw


def decode_frame(blob: bytes, magic: bytes = C.MAGIC_BYTES) -> Tuple[str, dict]:
    """Decode one complete frame; raises ValueError on malformed input."""
    if len(blob) < 24:
        raise ValueError("frame too short")
    if blob[:4] != magic:
        raise ValueError("bad magic")
    command = blob[4:16].rstrip(b"\x00").decode(errors="strict")
    if command not in COMMANDS:
        raise ValueError(f"unknown command {command!r}")
    length = struct.unpack("<I", blob[16:20])[0]
    if length > MAX_PAYLOAD:
        raise ValueError("payload too large")
    checksum = blob[20:24]
    payload_raw = blob[24:24 + length]
    if len(payload_raw) != length:
        raise ValueError("truncated payload")
    if dhash(payload_raw)[:4] != checksum:
        raise ValueError("checksum mismatch")
    payload = json.loads(payload_raw.decode()) if length else {}
    return command, payload


class FrameReader:
    """Incremental frame reader over a byte stream.

    The internal buffer is bounded (MAX_FRAME_BUFFER); feeding more data
    beyond the bound raises BufferError so the caller can drop the peer
    instead of letting a malicious stream exhaust memory.
    """

    def __init__(self, magic: bytes = C.MAGIC_BYTES,
                 max_buffer: int = C.MAX_FRAME_BUFFER):
        self.magic = magic
        self._buf = bytearray()
        self._max_buffer = max_buffer

    def feed(self, data: bytes):
        if len(self._buf) + len(data) > self._max_buffer:
            raise BufferError("frame buffer overflow")
        self._buf.extend(data)

    def next_frame(self) -> Optional[Tuple[str, dict]]:
        while True:
            if len(self._buf) < 24:
                return None
            # resync on magic; a peer on another network never matches, so
            # its stream is discarded as soon as the buffer drains
            if bytes(self._buf[:4]) != self.magic:
                idx = bytes(self._buf).find(self.magic)
                if idx == -1:
                    # keep a tail that could contain a partial magic
                    del self._buf[:-len(self.magic)]
                    return None
                del self._buf[:idx]
                continue
            length = struct.unpack("<I", self._buf[16:20])[0]
            if length > MAX_PAYLOAD:
                # unrecoverable in this frame; drop magic and resync
                del self._buf[:4]
                continue
            total = 24 + length
            if len(self._buf) < total:
                return None
            frame = bytes(self._buf[:total])
            del self._buf[:total]
            try:
                return decode_frame(frame, self.magic)
            except (ValueError, UnicodeDecodeError, json.JSONDecodeError):
                continue
