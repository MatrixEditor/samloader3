from __future__ import annotations

import os
import base64
import typing as t

from cryptography.hazmat.primitives.ciphers import (
    algorithms,
    modes,
    Cipher,
    CipherContext,
)
from cryptography.hazmat.primitives.padding import PKCS7

KEY_1 = b"hqzdurufm2c8mf6bsjezu1qgveouv7c7"
KEY_2 = b"w13r4cvf4hctaujv"


def aes_decrypt(data: bytes, key: bytes) -> bytes:
    """
    Decrypts data using AES encryption in CBC mode with PKCS7 padding.

    :param data: Encrypted data to be decrypted.
    :param key: AES encryption key.
    :return: Decrypted data.
    """
    iv = key[:16]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))

    decryptor = cipher.decryptor()
    decrypted = decryptor.update(data) + decryptor.finalize()
    return unpad(decrypted)


def aes_encrypt(data: bytes, key: bytes) -> bytes:
    """
    Encrypts data using AES encryption in CBC mode with PKCS7 padding.

    :param data: Data to be encrypted.
    :param key: AES encryption key.
    :return: Encrypted data.
    """
    iv = key[:16]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))

    encryptor = cipher.encryptor()
    return encryptor.update(pad(data)) + encryptor.finalize()


def get_key(nonce: str) -> bytes:
    """
    Generates an encryption key based on the provided nonce.

    :param nonce: Nonce used to generate the key.
    :return: Generated encryption key.
    """
    key = [KEY_1[ord(nonce[i]) % 16] for i in range(16)]
    return bytes(key) + KEY_2


def get_nonce(encrypted_nonce: str) -> str:
    """
    Decrypts and retrieves the original nonce from the encrypted nonce.

    :param encrypted_nonce: Encrypted nonce.
    :return: Decrypted original nonce.
    """
    data = base64.b64decode(encrypted_nonce)
    return aes_decrypt(data, KEY_1).decode()


def get_logic_check(data: str, nonce: str) -> str:
    """
    Performs a logic check using the provided data and nonce.

    :param data: Data for the logic check.
    :param nonce: Nonce used in the logic check.
    :return: Result of the logic check.
    """
    result = ""
    for char in nonce:
        result += data[ord(char) & 0xF]
    return result


def get_signature(nonce: str) -> str:
    """
    Generates a signature for the provided nonce.

    :param nonce: Nonce for which the signature is generated.
    :return: Generated signature.
    """
    key = get_key(nonce)
    data = aes_encrypt(nonce.encode(), key)
    return base64.b64encode(data).decode()


def get_file_decryptor(key: bytes) -> CipherContext:
    """
    Creates an AES decryption context for file decryption.

    :param key: AES decryption key.
    :return: AES decryption context.
    """
    cipher = Cipher(algorithms.AES(key), modes.ECB())
    return cipher.decryptor()


def unpad(data: bytes, block_size: int = 0x80) -> bytes:
    """
    Removes PKCS7 padding from the data.

    :param data: Padded data.
    :param block_size: Block size for PKCS7 padding.
    :return: Unpadded data.
    """
    unpadder = PKCS7(block_size).unpadder()
    return unpadder.update(data) + unpadder.finalize()


def pad(data: bytes, block_size: int = 0x80) -> bytes:
    """
    Adds PKCS7 padding to the data.

    :param data: Data to be padded.
    :param block_size: Block size for PKCS7 padding.
    :return: Padded data.
    """
    padder = PKCS7(block_size).padder()
    return padder.update(data) + padder.finalize()


def file_decrypt(
    path: str,
    out: str,
    key: bytes,
    block_size: int = 4096,
    key_version: t.Optional[str] = None,
) -> None:
    """
    Decrypts a file using a given key.

    :param path: Path to the input encrypted file.
    :type path: str
    :param out: Path to the output decrypted file.
    :type out: str
    :param key: Encryption key.
    :type key: bytes
    :param block_size: Size of the encryption block, defaults to 4096.
    :type block_size: int, optional
    :param key_version: Optional key version, defaults to None.
    :type key_version: t.Optional[str]
    :raises FileExistsError: Raised if the output path is the same as the input path.
    """
    total_size = os.stat(path).st_size
    cipher = get_file_decryptor(key)

    chunks = total_size // block_size + 1
    if os.path.isdir(out):
        name = os.path.basename(path).removesuffix(key_version or "")
        out = os.path.join(out, name)

    if os.path.abspath(path) == os.path.abspath(out):
        raise FileExistsError("Output can not be Input (path == out)!")

    with open(path, "rb") as istream, open(out, "wb") as ostream:
        for i in range(chunks):
            block = istream.read(block_size)
            if not block:
                break

            decrypted = cipher.update(block)
            if i == chunks - 1:
                # we actually don't need .finalize() here
                ostream.write(unpad(decrypted))
            else:
                ostream.write(decrypted)
