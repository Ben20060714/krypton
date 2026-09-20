"""Chiffrement réversible en trois couches.

Les couches appliquées sont, dans cet ordre :

1. Fernet (chiffrement symétrique authentifié, basé notamment sur AES) ;
2. représentation binaire, avec exactement huit bits par octet ;
3. représentation hexadécimale de la chaîne binaire.

La couche hexadécimale encode les *octets UTF-8* de la chaîne binaire.
Cette précision permet de conserver les zéros initiaux et rend chaque étape
parfaitement réversible.
"""

from __future__ import annotations

import binascii
from typing import Union

from cryptography.fernet import Fernet, InvalidToken


Key = Union[bytes, str]


def _key_as_bytes(key: Key) -> bytes:
    """Retourne une clé Fernet sous forme d'octets et valide son format."""
    key_bytes = key.encode("ascii") if isinstance(key, str) else key
    if not isinstance(key_bytes, bytes):
        raise TypeError("La clé doit être une clé Fernet en bytes ou en texte.")

    # La construction de Fernet valide la longueur et l'encodage de la clé.
    Fernet(key_bytes)
    return key_bytes


def _encrypt_layer(key: Key, message: str) -> bytes:
    """Applique la couche 1 et retourne le jeton Fernet sous forme d'octets."""
    if not isinstance(message, str):
        raise TypeError("Le message doit être une chaîne de caractères.")
    return Fernet(_key_as_bytes(key)).encrypt(message.encode("utf-8"))


def _bytes_to_binary(data: bytes) -> str:
    """Convertit chaque octet en huit caractères ``0`` ou ``1``."""
    return "".join(f"{byte:08b}" for byte in data)


def _binary_to_bytes(binary: str) -> bytes:
    """Convertit une chaîne binaire validée en octets."""
    if not binary or len(binary) % 8 != 0:
        raise ValueError("La chaîne binaire doit contenir un nombre de bits multiple de 8.")
    if any(bit not in "01" for bit in binary):
        raise ValueError("La chaîne binaire ne doit contenir que des 0 et des 1.")
    return bytes(
        int(binary[index : index + 8], 2)
        for index in range(0, len(binary), 8)
    )


def _binary_to_hex(binary: str) -> str:
    """Encode la chaîne binaire (ASCII) en hexadécimal."""
    _binary_to_bytes(binary)  # Valide aussi le format avant la couche 3.
    return binascii.hexlify(binary.encode("ascii")).decode("ascii")


def _hex_to_binary(hex_text: str) -> str:
    """Décode l'hexadécimal en chaîne binaire et valide son contenu."""
    if not isinstance(hex_text, str) or not hex_text:
        raise ValueError("Le texte hexadécimal doit être une chaîne non vide.")
    try:
        binary = binascii.unhexlify(hex_text).decode("ascii")
    except (binascii.Error, UnicodeDecodeError) as exc:
        raise ValueError("Le texte final n'est pas un hexadécimal valide.") from exc
    _binary_to_bytes(binary)
    return binary


def encrypt_message(message: str, key: Key) -> str:
    """Chiffre ``message`` en appliquant les trois couches 1 -> 2 -> 3.

    Args:
        message: Texte UTF-8 à chiffrer.
        key: Clé Fernet générée par :func:`Fernet.generate_key`, en bytes ou str.

    Returns:
        La chaîne hexadécimale finale.
    """
    encrypted_bytes = _encrypt_layer(key, message)
    binary = _bytes_to_binary(encrypted_bytes)
    return _binary_to_hex(binary)


def decrypt_message(cipher_text: str, key: Key) -> str:
    """Déchiffre ``cipher_text`` en appliquant les couches inverses 3 -> 2 -> 1."""
    binary = _hex_to_binary(cipher_text)
    encrypted_bytes = _binary_to_bytes(binary)
    try:
        plain_bytes = Fernet(_key_as_bytes(key)).decrypt(encrypted_bytes)
    except InvalidToken as exc:
        raise ValueError("Le texte ou la clé est invalide, ou le contenu a été altéré.") from exc
    try:
        return plain_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("Le message déchiffré n'est pas un texte UTF-8 valide.") from exc


if __name__ == "__main__":
    secret_key = Fernet.generate_key()
    secret_message = input("Saisissez le message secret : ")

    encrypted_bytes = _encrypt_layer(secret_key, secret_message)
    binary_text = _bytes_to_binary(encrypted_bytes)
    final_hex = _binary_to_hex(binary_text)

    print("\n--- Chiffrement ---")
    print(f"Clé Fernet générée : {secret_key.decode('ascii')}")
    print(f"Texte chiffré Fernet : {encrypted_bytes.decode('ascii')}")
    print(f"Chaîne binaire : {binary_text}")
    print(f"Résultat hexadécimal final : {final_hex}")

    recovered_message = decrypt_message(final_hex, secret_key)
    print("\n--- Décodage ---")
    print(f"Message retrouvé : {recovered_message}")
    print(f"Vérification : {'OK' if recovered_message == secret_message else 'ÉCHEC'}")
