# Traceur Mémoire C

Un outil de traçage mémoire pour C qui permet de détecter les fuites de mémoire, les erreurs d'allocation et de surveiller l'utilisation de la mémoire en temps réel. Il remplace les fonctions standards de gestion mémoire (`malloc`, `free`, etc.) par des versions instrumentées qui fournissent des informations détaillées sur l'utilisation de la mémoire.

## Fonctionnalités

- Traçage de toutes les allocations mémoire (`malloc`, `calloc`, `realloc`)
- Détection des fuites mémoire
- Détection des double-free
- Détection des buffer overflows
- Traçage des opérations sur la mémoire (`memset`, `memcpy`, `memmove`)
- Capture de la pile d'appel pour chaque opération
- Statistiques détaillées sur l'utilisation de la mémoire
- Support du logging dans un fichier

## Installation

### En tant que bibliothèque partagée

```bash
# Compilation de la bibliothèque
make lib

# Installation système (nécessite les droits root)
sudo make install
```

### En tant que programme de démonstration

```bash
make demo
```

## Fonctionnalités détaillées

### 1. Traçage des allocations

- Capture du fichier, de la fonction et de la ligne pour chaque allocation
- Enregistrement de la taille allouée
- Traçage de la pile d'appel
- Détection des erreurs d'alignement

### 2. Détection des erreurs

- Détection des pointeurs NULL
- Double free
- Usage après libération
- Dépassement de buffer
- Pointeurs invalides
- Corruptions mémoire

### 3. Statistiques

- Nombre total d'allocations
- Ratio mémoire libérée/allouée
- Compteurs pour chaque type d'opération
- Statistiques d'erreurs

## Format des logs

### Logs standards

```md
[2024-12-14 15:30:45] [INFO] Message d'information
[2024-12-14 15:30:46] [WARNING] Avertissement
[2024-12-14 15:30:47] [ERROR] Erreur
[2024-12-14 15:30:48] [CRITICAL] Erreur critique
[2024-12-14 15:30:49] [CALL] Appel de fonction
```

### Trace d'allocation

```md
[2024-12-14 18:28:22] [CALL] Fichier <src/track_06.c> fonction <main> ligne <006> - (appel#001) - malloc(10) -> 0x5637c5fca6e0
```

### Rapport de fuite

```md
[2024-12-14 18:28:22] [ERROR] 20 octets alloués à <src/track_06.c> fonction <main> ligne <024> -> 0x5637c5fca6e0
[2024-12-14 18:28:22] [INFO] Total des fuites: 1 bloc, 20 octets
```

## Messages d'erreur communs

1. "Double free détecté"
   - Cause : Tentative de libérer un pointeur déjà libéré
   - Solution : Vérifier la logique de libération de la mémoire

2. "Pointeur invalide"
   - Cause : Utilisation d'un pointeur non alloué ou mal aligné
   - Solution : Vérifier l'origine du pointeur

3. "Dépassement de buffer"
   - Cause : Tentative d'accès mémoire hors des limites allouées
   - Solution : Vérifier les tailles utilisées dans memcpy/memset

## Bonnes pratiques

1. Toujours vérifier le rapport final de fuites mémoire
2. Activer le logging fichier en développement
3. Utiliser les traces de pile pour déboguer
4. Vérifier les statistiques de réallocation pour optimiser

## Limitations

- Impact sur les performances en mode debug
- Surcoût mémoire pour le traçage
- Non thread-safe dans la version actuelle

## Exemple complet

```c
int main() {
    // Les fonctions standards sont automatiquement tracées
    char *str = malloc(100);
    memset(str, 0, 100);

    // Faire quelque chose avec str

    free(str);
    return 0;
}
```

Il faudra ensuite compiler votre programme après avoir mis à disposition la librairie

```bash
# Compilation de votre programme avec le traceur
gcc votre_programme.c -L/usr/local/lib -ltrack -o votre_programme

# Avec un Makefile existant, ajoutez :
LDFLAGS += -L/usr/local/lib -ltrack
```

## Notes sur les performances

Le traceur a un impact sur les performances :

- Surcoût pour chaque allocation/libération
- Écriture des logs
- Capture des traces de pile

En production, il est recommandé de désactiver le logging fichier si les performances sont critiques.
