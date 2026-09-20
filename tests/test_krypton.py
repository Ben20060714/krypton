import pytest
from cryptography.fernet import Fernet

import krypton
from krypton import decrypt_message, decrypt_with_password, encrypt_message, encrypt_with_password


def test_password_round_trip() -> None:
    message = "Message confidentiel — été 🛡️"
    cipher_text = encrypt_with_password(message, "un mot de passe robuste")

    assert cipher_text.startswith("K1$")
    assert decrypt_with_password(cipher_text, "un mot de passe robuste") == message


def test_wrong_password_is_rejected() -> None:
    cipher_text = encrypt_with_password("secret", "correct")

    with pytest.raises(ValueError):
        decrypt_with_password(cipher_text, "incorrect")


def test_tampered_ciphertext_is_rejected() -> None:
    cipher_text = encrypt_with_password("secret", "correct")
    tampered = cipher_text[:-1] + ("0" if cipher_text[-1] != "0" else "1")

    with pytest.raises(ValueError):
        decrypt_with_password(tampered, "correct")


def test_invalid_password_format_is_rejected() -> None:
    with pytest.raises(ValueError):
        decrypt_with_password("not-a-krypton-message", "password")


def test_legacy_key_api_remains_available() -> None:
    key = Fernet.generate_key()
    cipher_text = encrypt_message("legacy", key)

    assert decrypt_message(cipher_text, key) == "legacy"


def test_cli_writes_encrypted_output_file(tmp_path, monkeypatch) -> None:
    source = tmp_path / "message.txt"
    encrypted = tmp_path / "message.krypton"
    source.write_text("message à protéger", encoding="utf-8")
    monkeypatch.setattr(krypton.getpass, "getpass", lambda _prompt: "mot de passe robuste")

    assert krypton.main(["encrypt", "--input", str(source), "--output", str(encrypted), "--quiet"]) == 0
    assert encrypted.exists()
    assert encrypted.read_text(encoding="utf-8").startswith("K1$")
