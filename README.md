# Atelier TOTP et authentification à deux facteurs

Le site propose un parcours d’inscription et de connexion à deux facteurs, ainsi qu’un vérificateur autonome pour le générateur en ligne de commande.

Le site utilise Python 3 avec SQLite 3.35 ou supérieur et la bibliothèque système **libqrencode** pour produire le QR code localement. Sur Debian ou Ubuntu, le paquet s’appelle `libqrencode4`. Le générateur autonome utilise uniquement la bibliothèque standard de Python.

## Lancer le site

Depuis ce dossier, lancez le serveur et ouvrez <http://127.0.0.1:8000>.

```sh
python3 site-tests/server.py
```

## Inscription et connexion à deux facteurs

1. Ouvrez **Sign up**, choisissez un nom d’utilisateur et un mot de passe d’au moins 12 caractères.
2. Dans Microsoft Authenticator, appuyez sur **+**, choisissez **Other account** et scannez le QR du site. Saisissez le code à six chiffres du compte **Atelier TOTP**. La double authentification s’active et l’espace protégé s’ouvre après la confirmation.
3. Déconnectez-vous. Pour vous reconnecter, saisissez le nom et le mot de passe, puis un nouveau code de l’application. Un code déjà accepté, y compris à l’inscription, ne peut être soumis à nouveau. Attendez le code de la période suivante si nécessaire.

Le serveur utilise une base locale `site-tests/accounts.sqlite3` par défaut. L’option `--db` permet de choisir un fichier différent. Les sessions et les limites de tentatives sont également enregistrées dans cette base.

## Générateur et vérificateur autonomes

Dans un autre terminal, lancez le générateur puis collez le code affiché dans le **TOTP verifier** à la racine du site. Le générateur crée son propre secret partagé au premier lancement. Les comptes inscrits utilisent chacun un secret distinct, configuré dans leur application d’authentification.

```sh
python3 generateur-totp/totp.py
```

Relancez la commande pour récupérer le code en cours. Le générateur et le serveur utilisent automatiquement l’horloge de leur appareil. Le code a six chiffres et change toutes les 30 secondes.

## Tests reproductibles

Pour tester une heure fixe, exécutez les deux commandes avec le même horodatage. Le formulaire demande toujours uniquement le code.

```sh
python3 site-tests/server.py --at 59
python3 generateur-totp/totp.py --at 59
```

Les deux programmes acceptent aussi `--digits`, `--algorithm` et `--secret-file`. Par défaut, ils utilisent SHA-1 et le fichier privé `.totp-secret` à la racine du dossier. Si les projets sont déplacés dans des dossiers différents sur la même machine, donnez-leur le même chemin absolu avec `--secret-file`. Le serveur écoute uniquement sur l’interface locale.


Les options d’heure fixe, de fenêtre et d’algorithme du serveur s’appliquent au vérificateur autonome. Pour les comptes, le serveur utilise toujours l’heure réelle, SHA-1, six chiffres et la période de 30 secondes en cours.

## Tests automatisés

Depuis ce dossier, lancez les tests du parcours HTTP et du générateur.

```sh
PYTHONPATH=site-tests python3 -m unittest discover -s site-tests/tests -v
```
