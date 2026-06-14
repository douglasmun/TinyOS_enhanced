#!/usr/bin/env python3
"""
TinyOS ELF Signature Tool
=========================

This tool generates ECDSA P-256 signatures for ELF binaries and appends them
to the ELF file in a custom section format.

Signature Format:
-----------------
The signature is appended to the end of the ELF file as follows:

struct elf_signature {
    char magic[16];           // "TINYOS_SIG_V1\0\0\0"
    uint32_t sig_offset;      // Offset to signature data from file start
    uint32_t elf_size;        // Size of ELF without signature
    uint8_t pub_key_x[32];    // Public key X coordinate (big-endian)
    uint8_t pub_key_y[32];    // Public key Y coordinate (big-endian)
    uint8_t signature_r[32];  // Signature R component (big-endian)
    uint8_t signature_s[32];  // Signature S component (big-endian)
    uint8_t hash[32];         // SHA-256 hash of ELF
};

Total size: 184 bytes

Security:
---------
- Uses ECDSA with NIST P-256 curve (secp256r1)
- SHA-256 hash of ELF binary (excluding signature)
- 256-bit security level equivalent to AES-256
- Compatible with TinyOS ecdsa.c implementation

Usage:
------
    ./sign_elf.py <input.elf> [output.elf]

If output.elf is not specified, creates input.elf.signed
"""

import struct
import hashlib
import sys
import os

try:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric import utils
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.backends import default_backend
except ImportError:
    print("ERROR: cryptography library not found")
    print("Install with: pip3 install cryptography")
    sys.exit(1)

MAGIC = b"TINYOS_SIG_V1\x00\x00\x00"
SIGNATURE_SIZE = 184  # magic(16) + offset(4) + size(4) + pubkey(64) + sig(64) + hash(32)


def generate_keypair():
    """Generate ECDSA P-256 key pair"""
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key = private_key.public_key()
    return private_key, public_key


def sign_elf(elf_path, output_path, private_key=None, public_key=None):
    """
    Sign an ELF file with ECDSA P-256

    Args:
        elf_path: Path to input ELF file
        output_path: Path to output signed ELF file
        private_key: ECDSA private key (generates new if None)
        public_key: ECDSA public key (derives from private_key if None)

    Returns:
        (private_key, public_key, signature_bytes)
    """
    # Read ELF file
    with open(elf_path, 'rb') as f:
        elf_data = f.read()

    elf_size = len(elf_data)
    print(f"[*] ELF file size: {elf_size} bytes")

    # Generate key pair if not provided
    if private_key is None:
        print("[*] Generating new ECDSA P-256 key pair...")
        private_key, public_key = generate_keypair()
    elif public_key is None:
        public_key = private_key.public_key()

    # Compute SHA-256 hash of ELF
    elf_hash = hashlib.sha256(elf_data).digest()
    print(f"[*] ELF SHA-256: {elf_hash.hex()}")

    # Sign the hash. Use Prehashed: the ECDSA message digest z must be the
    # SHA-256 of the ELF (elf_hash), NOT SHA-256(elf_hash). The kernel verifier
    # (src/elf.c / src/ecdsa.c) passes computed_hash = SHA256(elf_data) directly
    # as z, so the signer must do the same or signatures never verify.
    print("[*] Signing ELF with ECDSA P-256 (prehashed)...")
    signature_der = private_key.sign(
        elf_hash,
        ec.ECDSA(utils.Prehashed(hashes.SHA256()))
    )

    # Extract r and s from DER-encoded signature
    # DER format: 0x30 <len> 0x02 <r_len> <r> 0x02 <s_len> <s>
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
    r, s = decode_dss_signature(signature_der)

    # Convert r and s to 32-byte big-endian
    r_bytes = r.to_bytes(32, byteorder='big')
    s_bytes = s.to_bytes(32, byteorder='big')

    # Get public key coordinates
    public_numbers = public_key.public_numbers()
    pub_x = public_numbers.x.to_bytes(32, byteorder='big')
    pub_y = public_numbers.y.to_bytes(32, byteorder='big')

    print(f"[*] Public key X: {pub_x.hex()}")
    print(f"[*] Public key Y: {pub_y.hex()}")
    print(f"[*] Signature R:  {r_bytes.hex()}")
    print(f"[*] Signature S:  {s_bytes.hex()}")

    # Build signature structure
    sig_offset = elf_size
    signature_struct = struct.pack(
        '<16sII',  # magic, sig_offset, elf_size (little-endian for x86)
        MAGIC,
        sig_offset,
        elf_size
    )
    signature_struct += pub_x + pub_y  # Public key (64 bytes)
    signature_struct += r_bytes + s_bytes  # Signature (64 bytes)
    signature_struct += elf_hash  # Hash (32 bytes)

    assert len(signature_struct) == SIGNATURE_SIZE, f"Signature size mismatch: {len(signature_struct)}"

    # Write signed ELF
    with open(output_path, 'wb') as f:
        f.write(elf_data)
        f.write(signature_struct)

    print(f"[+] Signed ELF written to: {output_path}")
    print(f"[+] Total size: {elf_size + SIGNATURE_SIZE} bytes ({elf_size} + {SIGNATURE_SIZE} signature)")

    return private_key, public_key, signature_struct


def verify_signature(signed_elf_path):
    """Verify signature on a signed ELF file"""
    with open(signed_elf_path, 'rb') as f:
        data = f.read()

    if len(data) < SIGNATURE_SIZE:
        print("[!] File too small to contain signature")
        return False

    # Extract signature from end
    sig_data = data[-SIGNATURE_SIZE:]
    elf_data = data[:-SIGNATURE_SIZE]

    # Parse signature structure
    magic = sig_data[0:16]
    if magic != MAGIC:
        print(f"[!] Invalid magic: {magic}")
        return False

    sig_offset, elf_size = struct.unpack('<II', sig_data[16:24])

    if elf_size != len(elf_data):
        print(f"[!] Size mismatch: expected {elf_size}, got {len(elf_data)}")
        return False

    pub_x = sig_data[24:56]
    pub_y = sig_data[56:88]
    r_bytes = sig_data[88:120]
    s_bytes = sig_data[120:152]
    stored_hash = sig_data[152:184]

    # Verify hash
    computed_hash = hashlib.sha256(elf_data).digest()
    if computed_hash != stored_hash:
        print(f"[!] Hash mismatch")
        print(f"    Stored:   {stored_hash.hex()}")
        print(f"    Computed: {computed_hash.hex()}")
        return False

    print(f"[+] Hash verification: PASS")
    print(f"[+] ELF SHA-256: {computed_hash.hex()}")

    # Reconstruct public key
    x = int.from_bytes(pub_x, byteorder='big')
    y = int.from_bytes(pub_y, byteorder='big')

    public_numbers = ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1())
    public_key = public_numbers.public_key(default_backend())

    # Reconstruct signature
    r = int.from_bytes(r_bytes, byteorder='big')
    s = int.from_bytes(s_bytes, byteorder='big')

    from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
    signature_der = encode_dss_signature(r, s)

    # Verify signature
    try:
        public_key.verify(
            signature_der,
            computed_hash,
            ec.ECDSA(utils.Prehashed(hashes.SHA256()))
        )
        print(f"[+] Signature verification: PASS")
        print(f"[+] Public key X: {pub_x.hex()}")
        print(f"[+] Public key Y: {pub_y.hex()}")
        return True
    except Exception as e:
        print(f"[!] Signature verification: FAIL")
        print(f"    Error: {e}")
        return False


def main():
    if len(sys.argv) < 2:
        print("Usage: sign_elf.py <input.elf> [output.elf]")
        print("")
        print("Commands:")
        print("  sign_elf.py input.elf              - Sign ELF (creates input.elf.signed)")
        print("  sign_elf.py input.elf output.elf   - Sign ELF (specify output)")
        print("  sign_elf.py --verify input.elf     - Verify signed ELF")
        sys.exit(1)

    if sys.argv[1] == '--verify':
        if len(sys.argv) < 3:
            print("Usage: sign_elf.py --verify <signed.elf>")
            sys.exit(1)

        result = verify_signature(sys.argv[2])
        sys.exit(0 if result else 1)

    input_path = sys.argv[1]
    output_path = sys.argv[2] if len(sys.argv) > 2 else f"{input_path}.signed"

    if not os.path.exists(input_path):
        print(f"ERROR: Input file not found: {input_path}")
        sys.exit(1)

    try:
        sign_elf(input_path, output_path)
        print("")
        print("[*] Verifying signature...")
        verify_signature(output_path)
    except Exception as e:
        print(f"ERROR: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
