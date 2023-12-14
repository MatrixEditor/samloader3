from __future__ import annotations

import base64

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
