# Krypton

Krypton est un script Python qui chiffre un message texte avec une clé Fernet
dérivée d'un mot de passe par Argon2id, puis applique deux représentations
réversibles :

1. dérivation de clé avec Argon2id ;
2. chiffrement symétrique authentifié avec Fernet ;
3. conversion des octets chiffrés en chaîne binaire ;
4. conversion de cette chaîne binaire en hexadécimal.

Le processus inverse restitue exactement le message original.

## Prérequis

- Python 3.9 ou une version ultérieure ;
- la bibliothèque `cryptography` 44 ou une version ultérieure.

Installation de la dépendance :

```bash
python -m pip install -e ".[dev]"
```

## Démarrage rapide

Depuis le dossier contenant `krypton.py`, lancez :

```bash
python krypton.py
```

Après installation, la commande `krypton` est également disponible :

```bash
krypton encrypt --input message.txt --output message.krypton
krypton decrypt --input message.krypton --output message.txt
```

Sans `--input` ou `--output`, l'entrée standard et la sortie standard sont
utilisées.

Le programme va :

1. demander un mot de passe sans l'afficher ;
2. générer un sel aléatoire et dériver une clé avec Argon2id ;
3. demander un message secret ;
4. afficher le résultat chiffré ;
5. le décoder et afficher le message retrouvé.

Le mot de passe est nécessaire pour déchiffrer le message. Le sel est inclus
dans le résultat chiffré et n'a pas besoin d'être secret.

## Tests et qualité

Lancer les tests et le contrôle statique localement :

```bash
pytest
ruff check .
```

## Utilisation dans un autre programme

```python
from krypton import decrypt_with_password, encrypt_with_password

message = "Message confidentiel"
password = "Mot de passe long et unique"

cipher_text = encrypt_with_password(message, password)
print(f"Texte chiffré : {cipher_text}")

original_message = decrypt_with_password(cipher_text, password)
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

### `encrypt_with_password(message, password)` et `decrypt_with_password(cipher_text, password)`

Ces fonctions utilisent Argon2id pour dériver une clé Fernet. Le résultat
contient le format, le sel et le texte chiffré. Le sel n'est pas secret, mais le
mot de passe doit rester confidentiel.

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
