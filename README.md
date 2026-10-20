# Registre du Syndic

Application web de gestion de syndic d'immeuble (copropriété) : étages, appartements et autres lots, cotisations mensuelles des copropriétaires, dépenses de l'immeuble, impayés, reçus, états imprimables (relevé par appartement et état global) et exports CSV.

- Plusieurs immeubles par compte, avec un sélecteur d'immeuble.
- Accès par **code**, sans compte : un code administrateur (tous les immeubles), et pour chaque immeuble un code de gestion (saisie) et un code de lecture seule facultatif.
- Les codes sont mémorisés sur l'appareil après la première saisie.
- Données stockées dans Supabase (tables `syndic_…`) : aucun accès direct aux tables, tout passe par des fonctions qui vérifient le code ; codes chiffrés ; blocage après 30 codes faux en 15 minutes.

## Fichiers

| Fichier | Rôle |
|---|---|
| `index.html` | L'application complète |
| `config.js` | Adresse et clé publique du projet Supabase |
| `supabase-schema.sql` | Création des tables et des règles d'accès |

## Mise en ligne

Le site est publié par **GitHub Pages** depuis la branche `main` : chaque modification envoyée sur `main` met le site à jour automatiquement en une à deux minutes.
