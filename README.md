# Registre du Syndic

Application web de gestion de syndic d'immeuble (copropriété) : étages, appartements et autres lots, cotisations mensuelles des copropriétaires, dépenses de l'immeuble, impayés, reçus, états imprimables (relevé par appartement et état global) et exports CSV.

- Plusieurs immeubles par compte, avec un sélecteur d'immeuble.
- Connexion par e-mail et mot de passe.
- Partage par immeuble : **gestionnaire** (peut saisir) ou **lecture seule** (conseil syndical, copropriétaires).
- Données stockées dans Supabase (tables `syndic_…`), protégées par des règles d'accès (RLS).

## Fichiers

| Fichier | Rôle |
|---|---|
| `index.html` | L'application complète |
| `config.js` | Adresse et clé publique du projet Supabase |
| `supabase-schema.sql` | Création des tables et des règles d'accès |

## Mise en ligne

Le site est publié par **GitHub Pages** depuis la branche `main` : chaque modification envoyée sur `main` met le site à jour automatiquement en une à deux minutes.

## Réglage Supabase à faire une fois

Dans Supabase : **Authentication → URL Configuration**, ajoutez l'adresse du site dans **Redirect URLs** (et dans **Site URL** si ce projet ne sert qu'à cette application). Sans ce réglage, les liens de confirmation d'e-mail et de réinitialisation de mot de passe renvoient vers une mauvaise adresse.
