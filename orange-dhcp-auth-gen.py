#!/usr/bin/python3

import sys
import hashlib
import secrets
import argparse

# DHCP authentication option generator for Orange Livebox
# Created from reverse engineering documented at:
# https://lafibre.info/remplacer-livebox/cacking-nouveau-systeme-de-generation-de-loption-90-dhcp/

def bytesToHex(b: bytes, separator: str = "") -> str:
    return b.hex() if len(separator) == 0 else b.hex(separator, 1)

def tlvBytes(type: int, value: bytes) -> bytes:
    return bytes([type, len(value) + 2]) + value

if __name__ == "__main__":
    USERNAME_PREFIX = "fti/"

    arg_parser = argparse.ArgumentParser(description="DHCP authentication option generator for Orange Livebox")
    arg_parser.add_argument("-v", "--verbose", dest="verbose", action="store_true", default=False, help="Print more information")
    arg_parser.add_argument("--separator", dest="separator", type=str, default=":", help="Hexadecimal separator")
    arg_parser.add_argument("username", type=str, help="FTI username")
    arg_parser.add_argument("password", type=str, default=None, nargs="?", help="FTI password")
    args = arg_parser.parse_args()

    verbose = args.verbose
    hex_separator = args.separator
    username = args.username if args.username.startswith(USERNAME_PREFIX) else f"{USERNAME_PREFIX}{args.username}"
    if args.password is None:
        from getpass import getpass
        password = getpass("Password: ")
    else:
        password = args.password

    salt_byte = secrets.token_bytes(1) # Salt of one random byte
    salt = secrets.token_bytes(16) # Salt of 16 random bytes
    password_hash = hashlib.md5(salt_byte + password.encode("ascii") + salt)

    if verbose:
        print(f"Hex separator: {hex_separator}")
        print(f"Username: {username}")
        print(f"Salt byte: {bytesToHex(salt_byte)}")
        print(f"Salt: {bytesToHex(salt)}")
        print(f"Hashed password (with salt): {bytesToHex(password_hash.digest())}")

    # Option header (11 bytes, unused)
    header = bytes([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])

    # Fixed options
    fixed_options = tlvBytes(0x1a, bytes([0x00, 0x00, 0x05, 0x58, 0x01, 0x03, 0x41]))

    # Other options
    username_option = tlvBytes(0x01, username.encode("ascii"))
    salt_option = tlvBytes(0x3c, salt)
    password_hash_option = tlvBytes(0x03, salt_byte + password_hash.digest())

    auth_data = header + fixed_options + username_option + salt_option + password_hash_option
    auth_str = bytesToHex(auth_data, hex_separator)
    print(auth_str)
