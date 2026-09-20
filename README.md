# Krypton

Krypton est un script Python qui applique trois couches réversibles à un
message texte :

1. chiffrement symétrique authentifié avec Fernet ;
2. conversion des octets chiffrés en chaîne binaire ;
3. conversion de cette chaîne binaire en hexadécimal.

Le processus inverse restitue exactement le message original.

## Prérequis

- Python 3.9 ou une version ultérieure ;
- la bibliothèque `cryptography`.

Installation de la dépendance :

```bash
python -m pip install cryptography
```

## Démarrage rapide

Depuis le dossier contenant `krypton.py`, lancez :

```bash
python krypton.py
```

Le programme va :

1. générer automatiquement une clé Fernet ;
2. demander un message secret ;
3. afficher le résultat de chaque couche ;
4. décoder le résultat et afficher le message retrouvé.

La clé affichée est nécessaire pour déchiffrer le message. En situation
réelle, ne l’affichez pas et ne la partagez pas avec le texte chiffré.

## Utilisation dans un autre programme

```python
from cryptography.fernet import Fernet

from krypton import decrypt_message, encrypt_message

key = Fernet.generate_key()
message = "Message confidentiel 🔐"

cipher_text = encrypt_message(message, key)
print(f"Texte chiffré : {cipher_text}")

original_message = decrypt_message(cipher_text, key)
assert original_message == message
print(original_message)
```

La clé peut également être fournie sous forme de chaîne ASCII :

```python
key_text = key.decode("ascii")
cipher_text = encrypt_message("Bonjour", key_text)
message = decrypt_message(cipher_text, key_text)
```

## Fonctionnement des couches

### Chiffrement

```text
message UTF-8
    -> Fernet
octets chiffrés
    -> 8 bits par octet
chaîne composée de 0 et de 1
    -> encodage hexadécimal des caractères binaires
texte hexadécimal final
```

La couche binaire utilise toujours huit bits par octet, y compris les zéros
initiaux. La couche hexadécimale encode les octets ASCII de la chaîne binaire,
ce qui garantit que chaque étape est entièrement réversible.

### Déchiffrement

`decrypt_message` applique les opérations dans l’ordre inverse :

```text
hexadécimal
    -> chaîne binaire
    -> octets chiffrés
    -> déchiffrement Fernet
    -> texte UTF-8 original
```

Fernet fournit un chiffrement authentifié : une clé incorrecte ou une donnée
modifiée provoque une erreur au lieu de produire silencieusement un résultat
invalide.

## API

### `encrypt_message(message, key)`

- `message` : chaîne de caractères à chiffrer ;
- `key` : clé Fernet en `bytes` ou en chaîne ASCII ;
- retourne : chaîne hexadécimale finale.

### `decrypt_message(cipher_text, key)`

- `cipher_text` : résultat produit par `encrypt_message` ;
- `key` : même clé Fernet que lors du chiffrement ;
- retourne : message texte original.

Une `ValueError` est levée si le texte est invalide, altéré ou si la clé ne
permet pas de le déchiffrer.

## Générer et conserver une clé

Pour générer une clé Fernet indépendante :

```python
from cryptography.fernet import Fernet

key = Fernet.generate_key()
print(key.decode("ascii"))
```

Une clé perdue ne peut pas être reconstituée. Pour un vrai projet, stockez-la
dans un gestionnaire de secrets ou une variable d’environnement protégée,
plutôt que dans le code source ou dans le dépôt Git.

## Limites et bonnes pratiques

- Le texte hexadécimal est une représentation, pas une couche de sécurité
  supplémentaire ; la confidentialité vient de Fernet.
- Le résultat est plus volumineux que le message d’origine à cause des trois
  conversions.
- Ne réutilisez pas une clé exposée ou compromise.
- Ce projet est adapté à une démonstration et à une intégration simple ; pour
  une application de production, ajoutez une gestion sécurisée des clés, des
  tests et une politique de rotation adaptée.
