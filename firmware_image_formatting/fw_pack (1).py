#!/usr/bin/env python3
"""
fw_pack.py — Ibex secure-boot firmware image packer
=====================================================

Wraps a raw Ibex .bin into the signed firmware image format consumed by
the boot-ROM header parser (Step 3) and boot FSM (Step 4).

Header layout (big-endian, 112 bytes = 0x70):
─────────────────────────────────────────────────────────────────────────
 Offset  Size  Field          Value / notes
─────────────────────────────────────────────────────────────────────────
 0x00    4 B   magic          0x49424558  ASCII "IBEX"
 0x04    2 B   version        (major << 8) | minor  — rollback protection
 0x06    2 B   flags          reserved 0x0000, word-aligns payload_len
 0x08    4 B   payload_len    firmware payload size in bytes
 0x0C    4 B   header_crc32   CRC-32 of bytes 0x00–0x0B (pre-CRC region)
 0x10   32 B   fw_sha256      SHA-256 digest of firmware payload
 0x30   32 B   ecdsa_r        P-256 ECDSA signature r component
 0x50   32 B   ecdsa_s        P-256 ECDSA signature s component
─────────────────────────────────────────────────────────────────────────
 0x70    N B   firmware payload  (raw Ibex .bin)
─────────────────────────────────────────────────────────────────────────

Design rationale
----------------
All verification metadata precedes the payload so the hardware boot ROM
can perform a single sequential SPI read:
  1. Read 0x70 bytes → parse header, validate CRC, cache hash + signature
  2. Stream payload → feed into SHA-256 engine word by word
  3. Compare computed digest against fw_sha256 from header
  4. Run ECDSA verification against ecdsa_r / ecdsa_s
No RAM buffer for the full image is required.

The version field encodes major.minor as a big-endian uint16 so the
hardware rollback check is a single 16-bit integer comparison against a
minimum version stored in PROM:  image_version >= prom_min_version.

The flags field is currently all-zero and reserved for future use (e.g.
compression flag, encryption flag). It keeps payload_len at offset 0x08,
which is a 4-byte-aligned address convenient for 32-bit SPI word reads.

Usage
-----
  # Generate a fresh P-256 key pair and sign
  python3 fw_pack.py firmware.bin --gen-key --version 1.2 --out firmware.img

  # Sign with an existing PEM private key
  python3 fw_pack.py firmware.bin --key privkey.pem --version 1.2 --out firmware.img

  # Verify a packed image
  python3 fw_pack.py firmware.img --verify --pubkey pubkey.pem

  # Human-readable header decode (no key needed — useful on the bench)
  python3 fw_pack.py firmware.img --dump
"""

import argparse
import hashlib
import struct
import sys
import zlib
from pathlib import Path

# ─────────────────────────────────────────────────────────────────────────────
# Optional dependency
# ─────────────────────────────────────────────────────────────────────────────
try:
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import (
        decode_dss_signature,
        encode_dss_signature,
    )
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.backends import default_backend
    _CRYPTO_OK = True
except ImportError:
    _CRYPTO_OK = False


# ─────────────────────────────────────────────────────────────────────────────
# Format constants — these are the ground truth for both this script and
# the HDL header parser.  Change here first, then update the HDL.
# ─────────────────────────────────────────────────────────────────────────────
MAGIC           = 0x49424558   # ASCII "IBEX"
HEADER_SIZE     = 0x70         # 112 bytes — fixed; HDL parser depends on this
PAYLOAD_OFFSET  = HEADER_SIZE

# Field offsets (bytes from start of image)
OFF_MAGIC       = 0x00
OFF_VERSION     = 0x04         # uint16: (major << 8) | minor
OFF_FLAGS       = 0x06         # uint16: reserved, must be 0x0000
OFF_PAYLOAD_LEN = 0x08         # uint32
OFF_HDR_CRC32   = 0x0C         # uint32: CRC-32 of bytes 0x00–0x0B
OFF_FW_SHA256   = 0x10         # 32 bytes
OFF_ECDSA_R     = 0x30         # 32 bytes  P-256 r
OFF_ECDSA_S     = 0x50         # 32 bytes  P-256 s

# Field sizes (bytes)
SZ_FW_SHA256    = 32
SZ_ECDSA_SCALAR = 32           # one P-256 field element
SZ_ECDSA_SIG    = SZ_ECDSA_SCALAR * 2   # r ‖ s


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────
def crc32_of(data: bytes) -> int:
    """Standard CRC-32 (Ethernet / ZIP polynomial)."""
    return zlib.crc32(data) & 0xFFFFFFFF


def version_word(major: int, minor: int) -> int:
    """Encode major.minor as a big-endian uint16."""
    return (major << 8) | minor


def parse_version_str(v: str):
    """'1.2'  →  (1, 2).  Raises ValueError on bad input."""
    parts = v.split(".")
    if len(parts) != 2:
        raise ValueError(f"Version must be major.minor, got '{v}'")
    major, minor = int(parts[0]), int(parts[1])
    if not (0 <= major <= 255 and 0 <= minor <= 255):
        raise ValueError("major and minor must each be 0–255")
    return major, minor


def sig_to_raw(r: int, s: int) -> bytes:
    """P-256 (r, s) integers → 64 raw bytes, big-endian."""
    return r.to_bytes(SZ_ECDSA_SCALAR, "big") + s.to_bytes(SZ_ECDSA_SCALAR, "big")


def raw_to_sig(raw: bytes):
    """64 raw bytes → (r, s) integers."""
    r = int.from_bytes(raw[:SZ_ECDSA_SCALAR], "big")
    s = int.from_bytes(raw[SZ_ECDSA_SCALAR:], "big")
    return r, s


def _require_crypto():
    if not _CRYPTO_OK:
        sys.exit(
            "ERROR: 'cryptography' package not found.\n"
            "Install with:  pip install cryptography"
        )


def _fail(msg: str):
    print(f"[fw_pack] ERROR: {msg}", file=sys.stderr)
    sys.exit(1)


# ─────────────────────────────────────────────────────────────────────────────
# Header builder
# ─────────────────────────────────────────────────────────────────────────────
def build_header(major: int, minor: int, flags: int,
                 payload_len: int,
                 fw_sha256: bytes,
                 ecdsa_r: bytes, ecdsa_s: bytes) -> bytes:
    """
    Assemble the 112-byte header.

    CRC-32 is computed over bytes 0x00–0x0B (the pre-CRC region) and
    written at 0x0C.  All integers big-endian.
    """
    if len(fw_sha256) != SZ_FW_SHA256:
        raise ValueError(f"fw_sha256 must be {SZ_FW_SHA256} bytes")
    if len(ecdsa_r) != SZ_ECDSA_SCALAR:
        raise ValueError(f"ecdsa_r must be {SZ_ECDSA_SCALAR} bytes")
    if len(ecdsa_s) != SZ_ECDSA_SCALAR:
        raise ValueError(f"ecdsa_s must be {SZ_ECDSA_SCALAR} bytes")

    # Pre-CRC region: 0x00–0x0B  (12 bytes)
    #   magic(4) + version(2) + flags(2) + payload_len(4)
    pre_crc = struct.pack(
        ">I H H I",
        MAGIC,                      # 0x00  4 B
        version_word(major, minor), # 0x04  2 B
        flags,                      # 0x06  2 B
        payload_len,                # 0x08  4 B
    )
    assert len(pre_crc) == 12

    crc     = crc32_of(pre_crc)
    crc_bytes = struct.pack(">I", crc)  # 0x0C  4 B

    header = (
        pre_crc     +   # 0x00–0x0B  12 B
        crc_bytes   +   # 0x0C–0x0F   4 B
        fw_sha256   +   # 0x10–0x2F  32 B
        ecdsa_r     +   # 0x30–0x4F  32 B
        ecdsa_s         # 0x50–0x6F  32 B
    )
    assert len(header) == HEADER_SIZE, \
        f"BUG: header is {len(header)} B, expected {HEADER_SIZE} B"
    return header


# ─────────────────────────────────────────────────────────────────────────────
# Header parser / validator
# ─────────────────────────────────────────────────────────────────────────────
class ParsedHeader:
    """
    Parse and structurally validate a raw image buffer.

    Raises ValueError on any structural problem (bad magic, bad CRC,
    non-zero flags, image too short).  Does NOT verify the ECDSA
    signature or the SHA-256 hash — those require the payload and key.
    """
    def __init__(self, raw: bytes):
        if len(raw) < HEADER_SIZE:
            raise ValueError(
                f"Image too short: {len(raw)} B < {HEADER_SIZE} B header"
            )

        magic, version, flags, payload_len = struct.unpack_from(
            ">I H H I", raw, 0
        )
        (stored_crc,) = struct.unpack_from(">I", raw, OFF_HDR_CRC32)
        fw_sha256 = raw[OFF_FW_SHA256   : OFF_FW_SHA256 + SZ_FW_SHA256]
        ecdsa_r   = raw[OFF_ECDSA_R     : OFF_ECDSA_R   + SZ_ECDSA_SCALAR]
        ecdsa_s   = raw[OFF_ECDSA_S     : OFF_ECDSA_S   + SZ_ECDSA_SCALAR]

        # ── Structural checks ──────────────────────────────────────────────
        if magic != MAGIC:
            raise ValueError(
                f"Bad magic: 0x{magic:08X}  (expected 0x{MAGIC:08X} = 'IBEX')"
            )
        if flags != 0x0000:
            raise ValueError(
                f"Non-zero flags: 0x{flags:04X}  "
                f"(reserved field — image may be from a newer packer)"
            )
        computed_crc = crc32_of(raw[0x00:0x0C])
        if computed_crc != stored_crc:
            raise ValueError(
                f"Header CRC mismatch — stored 0x{stored_crc:08X}, "
                f"computed 0x{computed_crc:08X}  (header corrupted?)"
            )

        self.major       = (version >> 8) & 0xFF
        self.minor       =  version       & 0xFF
        self.version     = version
        self.flags       = flags
        self.payload_len = payload_len
        self.header_crc  = stored_crc
        self.fw_sha256   = fw_sha256
        self.ecdsa_r     = ecdsa_r
        self.ecdsa_s     = ecdsa_s

    def __str__(self):
        return (
            f"  Magic       : IBEX  (0x{MAGIC:08X})\n"
            f"  Version     : {self.major}.{self.minor}"
            f"  (0x{self.version:04X})\n"
            f"  Flags       : 0x{self.flags:04X}\n"
            f"  Payload len : {self.payload_len} bytes\n"
            f"  Header CRC  : 0x{self.header_crc:08X}\n"
            f"  FW SHA-256  : {self.fw_sha256.hex()}\n"
            f"  ECDSA r     : {self.ecdsa_r.hex()}\n"
            f"  ECDSA s     : {self.ecdsa_s.hex()}"
        )


# ─────────────────────────────────────────────────────────────────────────────
# Command: pack  (sign firmware and write image)
# ─────────────────────────────────────────────────────────────────────────────
def cmd_pack(args):
    _require_crypto()

    firmware  = Path(args.firmware).read_bytes()
    major, minor = parse_version_str(args.version)
    fw_sha256 = hashlib.sha256(firmware).digest()

    print(f"[fw_pack] Firmware   : {args.firmware}  ({len(firmware)} bytes)")
    print(f"[fw_pack] Version    : {major}.{minor}")
    print(f"[fw_pack] SHA-256    : {fw_sha256.hex()}")

    # ── Load or generate private key ────────────────────────────────────────
    if args.gen_key:
        privkey = ec.generate_private_key(ec.SECP256R1(), default_backend())
        pem_priv = privkey.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
        pem_pub = privkey.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        stem      = Path(args.out).stem
        priv_path = Path(args.out).with_name(stem + ".privkey.pem")
        pub_path  = Path(args.out).with_name(stem + ".pubkey.pem")
        priv_path.write_bytes(pem_priv)
        pub_path.write_bytes(pem_pub)
        print(f"[fw_pack] New key pair generated")
        print(f"[fw_pack]   Private : {priv_path}  (keep secret)")
        print(f"[fw_pack]   Public  : {pub_path}  (goes into PROM)")
    else:
        pem_data = Path(args.key).read_bytes()
        privkey  = serialization.load_pem_private_key(
            pem_data, password=None, backend=default_backend()
        )

    # ── Sign ────────────────────────────────────────────────────────────────
    # privkey.sign() hashes the payload internally with SHA-256 before signing,
    # so we pass the raw firmware bytes — not the pre-computed hash.
    der_sig   = privkey.sign(firmware, ec.ECDSA(hashes.SHA256()))
    r, s      = decode_dss_signature(der_sig)
    ecdsa_r   = r.to_bytes(SZ_ECDSA_SCALAR, "big")
    ecdsa_s   = s.to_bytes(SZ_ECDSA_SCALAR, "big")
    print(f"[fw_pack] ECDSA r    : {ecdsa_r.hex()}")
    print(f"[fw_pack] ECDSA s    : {ecdsa_s.hex()}")

    # ── Assemble and write ──────────────────────────────────────────────────
    header  = build_header(major, minor, 0x0000,
                           len(firmware), fw_sha256, ecdsa_r, ecdsa_s)
    image   = header + firmware

    out_path = Path(args.out)
    out_path.write_bytes(image)
    print(f"[fw_pack] Image      : {out_path}  ({len(image)} bytes)")
    print(f"[fw_pack] DONE")


# ─────────────────────────────────────────────────────────────────────────────
# Command: verify  (check SHA-256 + ECDSA against a public key)
# ─────────────────────────────────────────────────────────────────────────────
def cmd_verify(args):
    _require_crypto()

    image = Path(args.firmware).read_bytes()

    # ── Parse header (structural checks only) ───────────────────────────────
    try:
        hdr = ParsedHeader(image)
    except ValueError as e:
        _fail(str(e))

    print("[fw_pack] Header:")
    print(hdr)

    # ── Extract payload ──────────────────────────────────────────────────────
    payload = image[PAYLOAD_OFFSET : PAYLOAD_OFFSET + hdr.payload_len]
    if len(payload) != hdr.payload_len:
        _fail(
            f"Image truncated: expected {hdr.payload_len} B payload, "
            f"got {len(payload)} B"
        )

    # ── SHA-256 check ────────────────────────────────────────────────────────
    computed_sha = hashlib.sha256(payload).digest()
    if computed_sha != hdr.fw_sha256:
        _fail(
            f"SHA-256 mismatch\n"
            f"  stored   : {hdr.fw_sha256.hex()}\n"
            f"  computed : {computed_sha.hex()}"
        )
    print("[fw_pack] SHA-256  : OK")

    # ── ECDSA check ──────────────────────────────────────────────────────────
    pub_pem = Path(args.pubkey).read_bytes()
    pubkey  = serialization.load_pem_public_key(pub_pem, backend=default_backend())
    r       = int.from_bytes(hdr.ecdsa_r, "big")
    s       = int.from_bytes(hdr.ecdsa_s, "big")
    der_sig = encode_dss_signature(r, s)
    try:
        pubkey.verify(der_sig, payload, ec.ECDSA(hashes.SHA256()))
    except Exception as exc:
        _fail(f"ECDSA verification FAILED: {exc}")
    print("[fw_pack] ECDSA    : OK")

    print("[fw_pack] Image is VALID ✓")


# ─────────────────────────────────────────────────────────────────────────────
# Command: dump  (print header fields, no key required)
# ─────────────────────────────────────────────────────────────────────────────
def cmd_dump(args):
    image = Path(args.firmware).read_bytes()
    try:
        hdr = ParsedHeader(image)
    except ValueError as e:
        _fail(str(e))

    payload      = image[PAYLOAD_OFFSET : PAYLOAD_OFFSET + hdr.payload_len]
    computed_sha = hashlib.sha256(payload).digest()
    sha_status   = "OK" if computed_sha == hdr.fw_sha256 else "MISMATCH"

    print("[fw_pack] === Image Dump ===")
    print(hdr)
    print(f"  SHA check   : {sha_status}")
    print(f"  Image total : {len(image)} bytes")
    print()
    print("  Field map:")
    print(f"    0x{OFF_MAGIC:02X}  magic")
    print(f"    0x{OFF_VERSION:02X}  version")
    print(f"    0x{OFF_FLAGS:02X}  flags")
    print(f"    0x{OFF_PAYLOAD_LEN:02X}  payload_len")
    print(f"    0x{OFF_HDR_CRC32:02X}  header_crc32")
    print(f"    0x{OFF_FW_SHA256:02X}  fw_sha256   (32 B)")
    print(f"    0x{OFF_ECDSA_R:02X}  ecdsa_r     (32 B)")
    print(f"    0x{OFF_ECDSA_S:02X}  ecdsa_s     (32 B)")
    print(f"    0x{PAYLOAD_OFFSET:02X}  payload     ({hdr.payload_len} B)")


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────
def main():
    p = argparse.ArgumentParser(
        description="Ibex secure-boot firmware image packer / verifier",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__.split("Usage")[1] if "Usage" in __doc__ else "",
    )
    p.add_argument(
        "firmware",
        help=".bin input (pack) or .img input (verify / dump)",
    )

    mode = p.add_mutually_exclusive_group()
    mode.add_argument(
        "--verify", action="store_true",
        help="Verify SHA-256 + ECDSA signature of a packed image",
    )
    mode.add_argument(
        "--dump", action="store_true",
        help="Print header fields (no key required)",
    )

    p.add_argument("--key",     metavar="PEM",
                   help="P-256 private key PEM (sign mode)")
    p.add_argument("--gen-key", action="store_true",
                   help="Generate a fresh P-256 key pair and save alongside --out")
    p.add_argument("--pubkey",  metavar="PEM",
                   help="P-256 public key PEM (verify mode)")
    p.add_argument("--version", default="1.0", metavar="MAJOR.MINOR",
                   help="Firmware version (default: 1.0)")
    p.add_argument("--out",     default="firmware.img", metavar="FILE",
                   help="Output image path (default: firmware.img)")

    args = p.parse_args()

    if args.verify:
        if not args.pubkey:
            p.error("--verify requires --pubkey")
        cmd_verify(args)
    elif args.dump:
        cmd_dump(args)
    else:
        if not (args.gen_key or args.key):
            p.error("pack mode requires --key <pem> or --gen-key")
        cmd_pack(args)


if __name__ == "__main__":
    main()
