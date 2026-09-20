# Krypton

Krypton est un outil Python de chiffrement de messages. Il utilise Argon2id
pour dériver une clé depuis un mot de passe, puis Fernet pour fournir un
chiffrement symétrique authentifié.

Les conversions binaire et hexadécimale sont uniquement des représentations
réversibles ; elles n’ajoutent pas de sécurité cryptographique.

## Fonctionnalités

- chiffrement et authentification avec Fernet ;
- dérivation de clé résistante aux attaques par dictionnaire avec Argon2id ;
- interface en ligne de commande pour fichiers, stdin et stdout ;
- API Python réutilisable ;
- validation des données et rejet des messages altérés ;
- tests automatisés et vérification CI.

## Prérequis

- Python 3.9 ou version ultérieure ;
- `cryptography` 44 ou version ultérieure.
- `rich` 13.7 ou version ultérieure pour l’affichage de la CLI.

## Installation

Pour utiliser Krypton :

```bash
python -m pip install .
```

Pour installer également les outils de développement :

```bash
python -m pip install -e ".[dev]"
```

## Utilisation en ligne de commande

Chiffrer un fichier :

```bash
krypton encrypt --input message.txt --output message.krypton
```

Déchiffrer le fichier :

```bash
krypton decrypt --input message.krypton --output message.txt
```

Options utiles :

```bash
krypton encrypt --input message.txt --output message.krypton --verbose
krypton decrypt --input message.krypton --output message.txt --force
krypton encrypt --quiet --input message.txt
krypton encrypt --json --input message.txt --output message.krypton
```

Par défaut, Krypton refuse d’écraser un fichier existant. Utilisez `--force`
explicitement si cela est souhaité. L’option `--json` fournit une sortie
adaptée aux scripts automatisés.

Le mot de passe est demandé sans être affiché. Sans `--input`, Krypton lit
depuis stdin ; sans `--output`, il écrit vers stdout :

```bash
echo "Message confidentiel" | krypton encrypt > message.krypton
krypton decrypt < message.krypton
```

Pour une démonstration interactive :

```bash
python krypton.py
```

Le mode interactif n’affiche pas le contenu chiffré complet afin de garder une
interface lisible. Pour récupérer le texte chiffré, utilisez la commande CLI
avec `--output` ou le mode `--quiet`.

Il vérifie également automatiquement le déchiffrement, mais ne réaffiche pas
le message en clair.

## Format chiffré

Les fonctions utilisant un mot de passe produisent un texte au format suivant :

```text
K1$sel-base64$contenu-hexadécimal
```

Le sel est aléatoire, stocké avec le message et n’a pas besoin d’être secret.
Le mot de passe, lui, ne doit jamais être enregistré dans le dépôt ou partagé
avec le texte chiffré.

## Utilisation Python

```python
from krypton import decrypt_with_password, encrypt_with_password

message = "Message confidentiel"
password = "un mot de passe long et unique"

cipher_text = encrypt_with_password(message, password)
original_message = decrypt_with_password(cipher_text, password)

assert original_message == message
```

L’API historique basée directement sur une clé Fernet reste disponible :

```python
from cryptography.fernet import Fernet
from krypton import decrypt_message, encrypt_message

key = Fernet.generate_key()
cipher_text = encrypt_message("Bonjour", key)
assert decrypt_message(cipher_text, key) == "Bonjour"
```

### API principale

#### `encrypt_with_password(message, password)`

Chiffre un message avec une clé dérivée par Argon2id. Retourne une chaîne au
format `K1$sel-base64$contenu-hexadécimal`.

#### `decrypt_with_password(cipher_text, password)`

Déchiffre un résultat produit par `encrypt_with_password`. Une `ValueError` est
levée si le format, le mot de passe ou le contenu est invalide.

#### `encrypt_message(message, key)` / `decrypt_message(cipher_text, key)`

API bas niveau utilisant directement une clé Fernet en `bytes` ou en texte
ASCII. Ces fonctions sont utiles pour une intégration qui gère déjà ses clés.

## Développement

Lancer les tests :

```bash
pytest
```

Lancer le contrôle statique :

```bash
ruff check .
```

La CI exécute automatiquement ces vérifications pour chaque push et chaque
pull request.

## Sécurité et limites

- Fernet assure la confidentialité et l’authenticité du message.
- Argon2id protège la dérivation depuis un mot de passe ; utilisez un mot de
  passe long, unique et conservé dans un gestionnaire de mots de passe.
- Ne stockez jamais les mots de passe ou les clés dans le code source.
- Le timestamp Fernet est visible dans le token ; il peut révéler le moment
  approximatif du chiffrement.
- Fernet charge le message complet en mémoire et convient donc surtout aux
  messages et fichiers de taille modérée.
- Les conversions binaire et hexadécimale augmentent la taille du résultat,
  sans renforcer le chiffrement.

Ce projet est destiné à l’apprentissage et à des intégrations simples. Une
application sensible ou de production doit faire l’objet d’une revue de
sécurité adaptée à son contexte. Voir également [SECURITY.md](SECURITY.md).

## Licence

Ce projet est distribué sous licence MIT. Voir [LICENSE](LICENSE).
