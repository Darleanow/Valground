#include <stddef.h>

int main(void) {
    // Test 1: Allocation de tailles bizarres
    char *str1 = malloc(0);  // Taille minimale invalide
    char *str2 = malloc((size_t)-1);  // Taille maximale invalide
    char *str3 = malloc(1024);  // Allocation normale
    
    // Test 2: Calloc avec overflow
    int *numbers1 = calloc(SIZE_MAX, sizeof(int));  // Overflow
    int *numbers2 = calloc(5, sizeof(int));  // Normal
    
    // Test 3: Memset hors limites
    memset(str3, 'A', 2048);  // Buffer overflow
    memset(NULL, 'B', 10);    // NULL pointer
    memset(str3, 'C', 1024);  // Normal
    str3[1023] = '\0';
    
    // Test 4: Memcpy avec chevauchement et dépassement
    char *str4 = malloc(1024);
    memcpy(str4, str3, 2048);         // Buffer overflow
    memcpy(str4, str3 + 500, 1024);   // Chevauchement
    memcpy(str4, NULL, 10);           // Source NULL
    memcpy(NULL, str3, 10);           // Destination NULL
    memcpy(str4, str3, 1024);         // Normal
    
    // Test 5: Memmove avec cas spéciaux
    char *str5 = malloc(1024);
    memmove(str5, str5 + 100, 2048);  // Buffer overflow
    memmove(NULL, str5, 10);          // NULL pointer
    memmove(str5, str5 + 10, 100);    // Chevauchement (devrait marcher)
    
    // Test 6: Realloc intensif
    str3 = realloc(str3, (size_t)-1);  // Taille invalide
    str3 = realloc(NULL, 1024);        // NULL pointer (équivalent à malloc)
    str3 = realloc(str3, 512);         // Réduction
    str3 = realloc(str3, 2048);        // Expansion
    
    // Test 7: Free multiple et invalid
    free(str4);
    free(str4);                // Double free
    free(str5);
    free(str5);                // Double free
    free(NULL);                // NULL free
    free((void*)0x12345678);   // Invalid pointer
    free((void*)1);            // Invalid pointer
    
    // Test 8: Allocation sans libération (fuites mémoire)
    void *leak1 = malloc(1024);
    void *leak2 = malloc(2048);
    memset(leak1, 0xFF, 1024);  // Utilisation de la mémoire qui va fuir
    
    // Test 9: Realloc sur pointeur déjà libéré
    void *ptr = malloc(100);
    free(ptr);
    ptr = realloc(ptr, 200);    // Realloc après free
    
    // Test 10: Utilisation après libération
    char *uaf = malloc(100);
    free(uaf);
    memset(uaf, 'X', 100);      // Use after free
    
    // Test 11: Alignement
    void *unaligned = (void*)((uintptr_t)malloc(100) + 1);  // Création d'un pointeur mal aligné
    free(unaligned);            // Tentative de free sur pointeur mal aligné
    
    // Test 12: Calloc avec multiplication overflow
    int *overflow = calloc(0x100000000, 0x100000000);
    
    // Test 13: Réallocation avec chevauchement
    char *overlap = malloc(100);
    memset(overlap, 'Y', 100);
    overlap = realloc(overlap, 50);    // Réduction
    overlap = realloc(overlap, 150);   // Extension
    
    // Test 14: Free dans le mauvais ordre
    char *array[10];
    for(int i = 0; i < 10; i++) {
        array[i] = malloc(100);
    }
    // Libération dans un ordre aléatoire
    free(array[5]);
    free(array[2]);
    free(array[8]);
    free(array[1]);
    free(array[9]);
    free(array[0]);
    free(array[6]);
    free(array[4]);
    free(array[3]);
    free(array[7]);
    
    // Test 15: Allocation en cascade
    void *cascade = malloc(100);
    for(int i = 0; i < 100; i++) {
        cascade = realloc(cascade, 100 + i);
    }
    
    return 0;  // Plusieurs fuites mémoire intentionnelles
}