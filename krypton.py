"""Chiffrement réversible avec dérivation de clé et trois couches.

Quand un mot de passe est utilisé, la clé est d'abord dérivée avec Argon2id.
Les couches appliquées ensuite sont, dans cet ordre :

1. Fernet (chiffrement symétrique authentifié, basé notamment sur AES) ;
2. représentation binaire, avec exactement huit bits par octet ;
3. représentation hexadécimale de la chaîne binaire.

La couche hexadécimale encode les *octets UTF-8* de la chaîne binaire.
Cette précision permet de conserver les zéros initiaux et rend chaque étape
parfaitement réversible.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import getpass
import json
import os
import sys
from pathlib import Path
from typing import Optional, Union

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table

    RICH_AVAILABLE = True
except ImportError:  # pragma: no cover - fallback for minimal installations
    RICH_AVAILABLE = False


Key = Union[bytes, str]
PASSWORD_FORMAT = "K1"
SALT_SIZE = 16
ARGON2_ITERATIONS = 3
ARGON2_LANES = 4
ARGON2_MEMORY_COST = 64 * 1024  # KiB (64 MiB)


def _key_from_password(password: str, salt: bytes) -> bytes:
    """Dérive une clé Fernet depuis un mot de passe et un sel."""
    if not isinstance(password, str) or not password:
        raise ValueError("Le mot de passe doit être une chaîne non vide.")
    if not isinstance(salt, bytes) or len(salt) < SALT_SIZE:
        raise ValueError("Le sel doit contenir au moins 16 octets.")

    derived_key = Argon2id(
        salt=salt,
        length=32,
        iterations=ARGON2_ITERATIONS,
        lanes=ARGON2_LANES,
        memory_cost=ARGON2_MEMORY_COST,
    ).derive(password.encode("utf-8"))
    return base64.urlsafe_b64encode(derived_key)


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


def encrypt_with_password(message: str, password: str) -> str:
    """Chiffre un message avec une clé dérivée du mot de passe par Argon2id.

    Le sel aléatoire est intégré au résultat afin de permettre le déchiffrement.
    Le format produit est ``K1$sel-base64$texte-hexadécimal``.
    """
    salt = os.urandom(SALT_SIZE)
    key = _key_from_password(password, salt)
    cipher_text = encrypt_message(message, key)
    salt_text = base64.urlsafe_b64encode(salt).decode("ascii")
    return f"{PASSWORD_FORMAT}${salt_text}${cipher_text}"


def decrypt_with_password(cipher_text: str, password: str) -> str:
    """Déchiffre un texte produit par :func:`encrypt_with_password`."""
    if not isinstance(cipher_text, str):
        raise ValueError("Le texte chiffré doit être une chaîne.")
    parts = cipher_text.split("$", 2)
    if len(parts) != 3 or parts[0] != PASSWORD_FORMAT:
        raise ValueError("Le format du texte chiffré est invalide.")
    try:
        salt = base64.urlsafe_b64decode(parts[1].encode("ascii"))
    except (ValueError, UnicodeEncodeError, binascii.Error) as exc:
        raise ValueError("Le sel du texte chiffré est invalide.") from exc
    key = _key_from_password(password, salt)
    return decrypt_message(parts[2], key)


def _read_text(path: Optional[str]) -> str:
    return Path(path).read_text(encoding="utf-8") if path else sys.stdin.read()


def _write_text(path: Optional[str], content: str) -> None:
    if path:
        Path(path).write_text(content, encoding="utf-8")
    else:
        print(content)


def _status(title: str, details: list[str], *, stderr: bool = False) -> None:
    """Affiche un statut lisible, avec Rich si la dépendance est disponible."""
    stream = sys.stderr if stderr else sys.stdout
    if RICH_AVAILABLE:
        table = Table(show_header=False, box=None, padding=(0, 1), expand=False)
        table.add_column(style="bold cyan", no_wrap=True)
        table.add_column(overflow="fold")
        for line in details:
            label, separator, value = line.partition(":")
            table.add_row(label + separator, value if separator else "")
        Console(file=stream).print(
            Panel(
                table,
                title=f"[bold green]KRYPTON · {title}[/bold green]",
                expand=False,
                border_style="green",
            )
        )
    else:
        print(f"KRYPTON · {title}", file=stream)
        print("─" * 42, file=stream)
        width = max((len(line.partition(":")[0]) for line in details), default=0)
        for detail in details:
            label, separator, value = detail.partition(":")
            if separator:
                print(f"  {label:<{width}} :{value}", file=stream)
            else:
                print(f"  {detail}", file=stream)


def _error(message: str, *, stderr: bool = True) -> None:
    stream = sys.stderr if stderr else sys.stdout
    if RICH_AVAILABLE:
        Console(file=stream).print(f"[bold red]✗ Erreur :[/bold red] {message}")
    else:
        print(f"Erreur : {message}", file=stream)


def _interactive() -> int:
    if RICH_AVAILABLE:
        Console().print("[bold cyan]KRYPTON[/bold cyan]")
        Console().print("─" * 38)
    else:
        print("KRYPTON")
        print("─" * 38)
    secret_password = getpass.getpass("Saisissez le mot de passe de sécurité : ")
    secret_message = input("Saisissez le message à sécuriser : ")

    final_cipher_text = encrypt_with_password(secret_message, secret_password)

    _status("Message chiffré", [
        "Algorithme: Argon2id + Fernet",
        f"Taille du résultat: {len(final_cipher_text)} caractères",
    ])

    recovered_message = decrypt_with_password(final_cipher_text, secret_password)
    _status("Message déchiffré", [
        f"Vérification: {'OK' if recovered_message == secret_message else 'ÉCHEC'}",
        "Message en clair: masqué",
    ])
    return 0


def main(argv: Optional[list[str]] = None) -> int:
    """Point d'entrée de la ligne de commande."""
    parser = argparse.ArgumentParser(description="Chiffrement sécurisé de messages.")
    subparsers = parser.add_subparsers(dest="command")
    for command in ("encrypt", "decrypt"):
        subparser = subparsers.add_parser(command, help=f"{command}er un fichier ou stdin")
        subparser.add_argument("-i", "--input", help="fichier d'entrée (stdin par défaut)")
        subparser.add_argument("-o", "--output", help="fichier de sortie (stdout par défaut)")
        subparser.add_argument("--force", action="store_true", help="autorise l'écrasement d'un fichier")
        subparser.add_argument("--quiet", action="store_true", help="désactive les messages de statut")
        subparser.add_argument("--verbose", action="store_true", help="affiche les détails de l'opération")
        subparser.add_argument("--json", action="store_true", help="retourne le résultat au format JSON")

    args = parser.parse_args(argv)
    if args.command is None:
        return _interactive()

    if args.output and Path(args.output).exists() and not args.force:
        parser.error(f"le fichier de sortie existe déjà : {args.output} (utilisez --force)")

    password = getpass.getpass("Mot de passe : ")
    try:
        content = _read_text(args.input)
        result = (
            encrypt_with_password(content, password)
            if args.command == "encrypt"
            else decrypt_with_password(content.strip(), password)
        )
        if args.json:
            if args.output:
                _write_text(args.output, result)
            payload = {
                "status": "ok",
                "operation": args.command,
                "input": args.input or "stdin",
                "output": args.output or "stdout",
                "algorithm": "Argon2id + Fernet",
            }
            if not args.output:
                payload["data"] = result
            print(json.dumps(payload, ensure_ascii=False))
        else:
            _write_text(args.output, result)
            if not args.quiet:
                details = [
                    f"Entrée: {args.input or 'stdin'}",
                    f"Sortie: {args.output or 'stdout'}",
                    "Algorithme: Argon2id + Fernet",
                    "Statut: Protégé",
                ]
                if args.verbose:
                    details.append(f"Format: {PASSWORD_FORMAT}")
                _status("Données chiffrées" if args.command == "encrypt" else "Données déchiffrées", details, stderr=not args.output)
    except (OSError, ValueError) as exc:
        _error(str(exc))
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
