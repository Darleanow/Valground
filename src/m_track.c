#include "records.h"
#include "logger.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <execinfo.h>
#include <ctype.h>
#include <unistd.h>

#define MAX_ALLOCATION_SIZE (SIZE_MAX / 2)
#define MIN_ALLOCATION_SIZE (1)
#define CANARY_VALUE (0xDEADBEEF)
#define ALIGNMENT_MASK (~(sizeof(void *) - 1))

static MemoryEnv env = {0};

static struct
{
    ErrorStats errors;
    size_t peak_memory;
    time_t start_time;
    size_t realloc_count_resize;
    size_t realloc_count_move;
    size_t alignment_errors;
    size_t overflow_attempts;
} global_stats = {0};

static void print_stack_trace(const CallStack *stack)
{
    char **symbols = backtrace_symbols(stack->frames, stack->depth);
    if (!symbols)
    {
        LOG(logger, CRITICAL, "Impossible de récupérer les symboles de la pile d'appels");
        return;
    }

    LOG(logger, INFO, "Trace de la pile d'appel:");

    for (int i = 0; i < stack->depth; i++)
    {
        LOG(logger, INFO, "  #%-2d %s", i, symbols[i]);
    }
    free(symbols);
}

static void capture_stack(CallStack *stack)
{
    stack->depth = backtrace(stack->frames, STACK_TRACE_DEPTH);

    if (stack->depth <= 0)
    {
        LOG(logger, WARNING, "Échec de la capture de la pile d'appels");
        stack->depth = 0;
    }
    else if (stack->depth >= STACK_TRACE_DEPTH)
    {
        LOG(logger, WARNING, "Pile d'appels tronquée (plus de %d frames)", STACK_TRACE_DEPTH);
    }
}

static bool validate_pointer(void *ptr, const char *op, char *file, const char *func, int line)
{
    if (!ptr)
    {
        LOG(logger, ERROR, "Pointeur NULL détecté [%s] <%s:%d> %s",
            op, file, line, func);
        return false;
    }

    if ((uintptr_t)ptr < 4096)
    {
        LOG(logger, ERROR, "Pointeur dans la page zéro %p [%s] <%s:%d> %s", ptr, op, file, line, func);
        return false;
    }

    return true;
}

static MemoryCell* find_cell_for_ptr(void* ptr)
{
    uintptr_t target = (uintptr_t)ptr;
    for (size_t i = 0; i < env.allocations->capacity; i++)
    {
        HashNode *current = env.allocations->buckets[i];
        while (current)
        {
            uintptr_t start = (uintptr_t)current->key;
            uintptr_t end = start + current->value.block_size;
            if (target >= start && target < end && current->value.is_allocated)
            {
                return &current->value;
            }
            current = current->next;
        }
    }
    return NULL;
}

static bool validate_size(size_t size, char *file, const char *func, int line)
{
    if (size < MIN_ALLOCATION_SIZE)
    {
        LOG(logger, ERROR, "ERREUR: Taille d'allocation trop petite (%zu) <%s:%d> %s", size, file, line, func);
        return false;
    }

    if (size > MAX_ALLOCATION_SIZE)
    {
        LOG(logger, ERROR, "ERREUR CRITIQUE: Taille d'allocation excessive (%zu) <%s:%d> %s", size, file, line, func);
        global_stats.overflow_attempts++;
        return false;
    }

    return true;
}

static void handle_error(const char *msg, char *file, const char *func, int line)
{
    global_stats.errors.error_count++;
    global_stats.errors.consecutive_errors++;
    time_t now = time(NULL);

    if (global_stats.errors.error_count == 1)
    {
        global_stats.errors.first_error_time = now;
    }
    global_stats.errors.last_error_time = now;
    strncpy(global_stats.errors.last_error_msg, msg, 255);

    LOG(logger, ERROR, "Fichier <%s> fonction %s ligne <%03d> -  #%zu: %s",
        file, func, line, global_stats.errors.error_count, msg);

    if (global_stats.errors.consecutive_errors >= MAX_CONSECUTIVE_ERRORS)
    {
        LOG(logger, CRITICAL, "Trop d'erreurs consécutives (%zu) - Arrêt du programme",
            global_stats.errors.consecutive_errors);
        abort();
    }
}

static size_t hash_address(void *addr)
{
    return ((uintptr_t)addr) % HASH_SIZE;
}

static HashMap *hashmap_create(size_t initial_capacity)
{
    HashMap *map = malloc(sizeof(HashMap));
    if (!map)
        return NULL;

    map->buckets = calloc(initial_capacity, sizeof(HashNode *));
    if (!map->buckets)
    {
        free(map);
        return NULL;
    }

    map->capacity = initial_capacity;
    map->size = 0;
    return map;
}

static void hashmap_resize(HashMap *map, size_t new_capacity)
{
    HashNode **new_buckets = calloc(new_capacity, sizeof(HashNode *));
    if (!new_buckets)
    {
        return;
    }

    for (size_t i = 0; i < map->capacity; i++)
    {
        HashNode *current = map->buckets[i];
        while (current)
        {
            HashNode *next = current->next;
            size_t new_index = ((uintptr_t)current->key) % new_capacity;
            current->next = new_buckets[new_index];
            new_buckets[new_index] = current;
            current = next;
        }
    }

    free(map->buckets);
    map->buckets = new_buckets;
    map->capacity = new_capacity;
}

static void hashmap_put(HashMap *map, void *key, MemoryCell *value)
{
    size_t index = hash_address(key);
    HashNode *node = malloc(sizeof(HashNode));
    if (!node)
    {
        return;
    }

    node->key = key;
    node->value = *value;
    node->next = map->buckets[index];
    map->buckets[index] = node;
    map->size++;

    float load_factor = (float)map->size / map->capacity;
    if (load_factor > LOAD_FACTOR_THRESHOLD)
    {
        hashmap_resize(map, map->capacity * 2);
    }
}

static MemoryCell *hashmap_get(HashMap *map, void *key)
{
    size_t index = hash_address(key);
    HashNode *current = map->buckets[index];

    while (current)
    {
        if (current->key == key)
        {
            return &current->value;
        }
        current = current->next;
    }
    return NULL;
}

static void hashmap_remove(HashMap *map, void *key)
{
    size_t index = hash_address(key);
    HashNode *current = map->buckets[index];
    HashNode *prev = NULL;

    while (current)
    {
        if (current->key == key)
        {
            if (prev)
            {
                prev->next = current->next;
            }
            else
            {
                map->buckets[index] = current->next;
            }
            free(current);
            map->size--;
            return;
        }
        prev = current;
        current = current->next;
    }
}

static void report_memory_leaks(void)
{
    size_t leak_count = 0;
    size_t leaked_bytes = 0;

    TITLE(logger, "Détection des fuites mémoire");
    for (size_t i = 0; i < env.allocations->capacity; i++)
    {
        HashNode *current = env.allocations->buckets[i];
        while (current)
        {
            if (current->value.is_allocated)
            {
                leak_count++;
                leaked_bytes += current->value.block_size;
                LOG(logger, ERROR, "%zu octets alloués à <%s> fonction <%s> ligne <%03d> -> %p",
                    current->value.block_size,
                    current->value.file,
                    current->value.function,
                    current->value.line,
                    current->value.address);
            }
            current = current->next;
        }
    }

    if (leak_count > 0)
    {
        LOG(logger, INFO, "Total des fuites: %zu bloc%s, %zu octet%s",
            leak_count, leak_count > 1 ? "s" : "",
            leaked_bytes, leaked_bytes > 1 ? "s" : "");
    }
}

static void cleanup_unfreed_memory(void)
{
    size_t cleanup_count = 0;
    size_t cleanup_bytes = 0;

    TITLE(logger, "Nettoyage mémoire");
    for (size_t i = 0; i < env.allocations->capacity; i++)
    {
        HashNode *current = env.allocations->buckets[i];
        while (current)
        {
            HashNode *next = current->next;
            if (current->value.is_allocated)
            {
                cleanup_count++;
                cleanup_bytes += current->value.block_size;

                LOG(logger, WARNING, "Nettoyage forcé: %zu octets alloués à <%s:%d> %s -> %p",
                    current->value.block_size,
                    current->value.file,
                    current->value.line,
                    current->value.function,
                    current->value.address);

                free(current->value.address);
                current->value.is_allocated = false;
                current->value.free_time = time(NULL);
                capture_stack(&current->value.free_stack);
                env.total_freed += current->value.block_size;
            }
            current = next;
        }
    }

    if (cleanup_count > 0)
    {
        LOG(logger, INFO, "Total nettoyé: %zu bloc%s, %zu octet%s",
            cleanup_count, cleanup_count > 1 ? "s" : "",
            cleanup_bytes, cleanup_bytes > 1 ? "s" : "");
    }
    else
    {
        LOG(logger, INFO, "Aucun bloc à nettoyer");
    }
}

static void memory_env_clean(void)
{
    time_t t = time(NULL);
    struct tm *tm_info = localtime(&t);
    char date_str[64];
    strftime(date_str, sizeof(date_str), "%a %b %d %H:%M:%S %Y", tm_info);

    char hostname[1024];
    gethostname(hostname, sizeof(hostname));
    char cwd[1024];
    if (getcwd(cwd, sizeof(cwd)) == NULL)
    {
        strcpy(cwd, "INCONNU");
    }
    TITLE(logger, "Informations éxecution");
    LOG(logger, INFO, "Date          : %s", date_str);
    LOG(logger, INFO, "Utilisateur   : %s", getenv("USER") ? getenv("USER") : "INCONNU");
    LOG(logger, INFO, "Hôte          : %s", hostname);
    LOG(logger, INFO, "Chemin        : %s", cwd);
    TITLE(logger, "Bilan final");
    LOG(logger, INFO, "Total mémoire allouée  : %zu octet%s",
        env.total_allocated, env.total_allocated > 1 ? "s" : "");
    LOG(logger, INFO, "Total mémoire libérée  : %zu octet%s",
        env.total_freed, env.total_freed > 1 ? "s" : "");
    LOG(logger, INFO, "Ratio                  : %.2f%%",
        (env.total_freed > 0) ? (float)env.total_freed / (float)env.total_allocated * 100. : 0);
    TITLE(logger, "Statistiques d'appels");
    LOG(logger, INFO, "malloc                 : %zu appel%s",
        env.malloc_count, env.malloc_count > 1 ? "s" : "");
    LOG(logger, INFO, "calloc                 : %zu appel%s",
        env.calloc_count, env.calloc_count > 1 ? "s" : "");
    LOG(logger, INFO, "realloc                : %zu appel%s",
        env.realloc_count, env.realloc_count > 1 ? "s" : "");
    LOG(logger, INFO, "memset                 : %zu appel%s",
        env.memset_count, env.memset_count > 1 ? "s" : "");
    LOG(logger, INFO, "memcpy                 : %zu appel%s",
        env.memcpy_count, env.memcpy_count > 1 ? "s" : "");
    LOG(logger, INFO, "memmove                : %zu appel%s",
        env.memmove_count, env.memmove_count > 1 ? "s" : "");
    LOG(logger, INFO, "free corrects          : %zu appel%s",
        env.free_count, env.free_count > 1 ? "s" : "");
    LOG(logger, INFO, "free incorrects        : %zu appel%s",
        env.free_errors, env.free_errors > 1 ? "s" : "");

    report_memory_leaks();

    cleanup_unfreed_memory();

    if (env.allocations)
    {
        free(env.allocations->buckets);
        free(env.allocations);
    }
}

static void memory_env_init(void)
{
    if (env.is_active)
        return;

    TITLE(logger, "Informations d'analyse");

    env.allocations = hashmap_create(HASH_SIZE);
    if (!env.allocations)
    {
        LOG(logger, CRITICAL, "Impossible d'initialiser le traceur mémoire");
        exit(1);
    }

    env.malloc_count = 0;
    env.calloc_count = 0;
    env.realloc_count = 0;
    env.memset_count = 0;
    env.memcpy_count = 0;
    env.memmove_count = 0;
    env.free_count = 0;
    env.free_errors = 0;
    env.total_allocated = 0;
    env.total_freed = 0;
    env.is_active = true;

    atexit(memory_env_clean);
}

void *c_malloc(char *file, const char *func, int line, size_t size)
{
    memory_env_init();

    if (!validate_size(size, file, func, line))
    {
        handle_error("Validation de taille échouée", file, func, line);
        return NULL;
    }

    void *p = malloc(size);
    if (!p)
    {
        handle_error("Échec d'allocation", file, func, line);
        return NULL;
    }

    if (!validate_pointer(p, "malloc", file, func, line))
    {
        handle_error("Pointeur invalide", file, func, line);
        free(p);
        return NULL;
    }

    MemoryCell cell = {
        .address = p,
        .block_size = size,
        .is_allocated = true,
        .file = file,
        .function = func,
        .line = line,
        .canary = CANARY_VALUE,
        .alloc_time = time(NULL)};
    capture_stack(&cell.alloc_stack);

    hashmap_put(env.allocations, p, &cell);

    env.total_allocated += size;
    env.malloc_count++;
    if (env.total_allocated - env.total_freed > global_stats.peak_memory)
    {
        global_stats.peak_memory = env.total_allocated - env.total_freed;
    }

    LOG(logger, CALL, "Fichier <%s> fonction <%s> ligne <%03d> - (appel#%03zu) - malloc(%zu) -> %p",
        file, func, line, env.malloc_count, size, p);

    global_stats.errors.consecutive_errors = 0;
    return p;
}

void *c_calloc(char *file, const char *func, int line, size_t nmemb, size_t size)
{
    memory_env_init();

    if (size > 0 && nmemb > SIZE_MAX / size)
    {
        handle_error("Dépassement arithmétique dans calloc", file, func, line);
        return NULL;
    }

    size_t total_size = nmemb * size;
    if (!validate_size(total_size, file, func, line))
    {
        handle_error("Validation de taille échouée pour calloc", file, func, line);
        return NULL;
    }

    void *p = calloc(nmemb, size);
    if (!p)
    {
        handle_error("Échec d'allocation avec calloc", file, func, line);
        return NULL;
    }

    if (!validate_pointer(p, "calloc", file, func, line))
    {
        handle_error("Pointeur invalide", file, func, line);
        free(p);
        return NULL;
    }

    MemoryCell cell = {
        .address = p,
        .block_size = total_size,
        .is_allocated = true,
        .file = file,
        .function = func,
        .line = line,
        .canary = CANARY_VALUE,
        .alloc_time = time(NULL)};
    capture_stack(&cell.alloc_stack);

    env.total_allocated += total_size;
    env.calloc_count++;
    if (env.total_allocated - env.total_freed > global_stats.peak_memory)
    {
        global_stats.peak_memory = env.total_allocated - env.total_freed;
    }

    hashmap_put(env.allocations, p, &cell);

    LOG(logger, CALL, "Fichier <%s> fonction <%s> ligne <%03d> - (appel#%03zu) - calloc(%zu, %zu) -> %p",
        file, func, line, env.calloc_count, nmemb, size, p);

    global_stats.errors.consecutive_errors = 0;
    return p;
}

void *c_realloc(char *file, const char *func, int line, void *ptr, size_t new_size)
{
    memory_env_init();

    if (!ptr)
    {
        return c_malloc(file, func, line, new_size);
    }

    if (!validate_size(new_size, file, func, line))
    {
        handle_error("Validation de taille échouée pour realloc", file, func, line);
        return NULL;
    }

    if (!validate_pointer(ptr, "realloc", file, func, line))
    {
        handle_error("Pointeur invalide", file, func, line);
        return NULL;
    }

    MemoryCell *old_cell = hashmap_get(env.allocations, ptr);
    if (!old_cell)
    {
        handle_error("Tentative de realloc sur un pointeur non alloué", file, func, line);
        return NULL;
    }

    if (!old_cell->is_allocated)
    {
        handle_error("Tentative de realloc sur un pointeur déjà libéré", file, func, line);
        LOG(logger, INFO, "  Libération précédente: <%s:%d> %s",
            old_cell->file, old_cell->line, old_cell->function);

        print_stack_trace(&old_cell->free_stack);
        return NULL;
    }

    if (old_cell->canary != CANARY_VALUE)
    {
        handle_error("Corruption de mémoire détectée avant realloc", file, func, line);
        return NULL;
    }

    size_t old_size = old_cell->block_size;
    size_t realloc_count = ++env.realloc_count;

    hashmap_remove(env.allocations, ptr);

    LOG(logger, CALL, "Fichier <%s> fonction <%s> ligne <%03d> - (appel#%03zu) - realloc(%p, %zu)",
        file, func, line, realloc_count, ptr, new_size);

    void *new_ptr = realloc(ptr, new_size);
    LOG(logger, WARNING, " -> Nouvelle addresse: %p", new_ptr);

    if (!new_ptr)
    {
        handle_error("Échec de realloc", file, func, line);
        return NULL;
    }

    env.total_freed += old_size;
    env.total_allocated += new_size;

    if (new_ptr != ptr)
    {
        global_stats.realloc_count_move++;
    }

    if (new_size != old_size)
    {
        global_stats.realloc_count_resize++;
    }

    MemoryCell new_cell = {
        .address = new_ptr,
        .block_size = new_size,
        .is_allocated = true,
        .file = file,
        .function = func,
        .line = line,
        .canary = CANARY_VALUE,
        .alloc_time = time(NULL)};
    capture_stack(&new_cell.alloc_stack);

    hashmap_put(env.allocations, new_ptr, &new_cell);
    global_stats.errors.consecutive_errors = 0;
    return new_ptr;
}

void *c_memset(char *file, const char *func, int line, void *s, int c, size_t n)
{
    memory_env_init();

    if (!validate_pointer(s, "memset", file, func, line))
    {
        handle_error("Pointeur invalide", file, func, line);
        return NULL;
    }

    MemoryCell *cell = hashmap_get(env.allocations, s);
    if (!cell || !cell->is_allocated)
    {
        handle_error("Tentative de memset sur un pointeur non valide", file, func, line);
        return NULL;
    }

    if (n > cell->block_size)
    {
        handle_error("Dépassement de buffer dans memset", file, func, line);
        return NULL;
    }

    void *result = memset(s, c, n);
    env.memset_count++;

    LOG(logger, CALL, "Fichier <%s> fonction <%s> ligne <%03d> - (appel#%03zu) - memset(%p, %d, %zu)",
        file, func, line, env.memset_count, s, c, n);

    return result;
}

void *c_memcpy(char *file, const char *func, int line, void *dest, const void *src, size_t n)
{
    memory_env_init();

    if (!validate_pointer(dest, "memcpy dest", file, func, line) ||
        !validate_pointer((void *)src, "memcpy src", file, func, line))
    {
        if (!validate_pointer(dest, "memcpy dest", file, func, line))
        {
            handle_error("Pointeur destination invalide", file, func, line);
            return NULL;
        }

        handle_error("Pointeur source invalide", file, func, line);
        return NULL;
    }

    MemoryCell *dest_cell = hashmap_get(env.allocations, dest);
    MemoryCell *src_cell = hashmap_get(env.allocations, (void *)src);

    if (!dest_cell || !dest_cell->is_allocated)
    {
        handle_error("Destination de memcpy non valide", file, func, line);
        return NULL;
    }

    if (!src_cell || !src_cell->is_allocated)
    {
        handle_error("Source de memcpy non valide", file, func, line);
        return NULL;
    }

    if (n > dest_cell->block_size || n > src_cell->block_size)
    {
        handle_error("Dépassement de buffer dans memcpy", file, func, line);
        return NULL;
    }

    const char *src_end = (const char *)src + n;
    const char *dest_end = (const char *)dest + n;

    if (((const char *)src <= (const char *)dest && src_end > (const char *)dest) ||
        ((const char *)dest <= (const char *)src && dest_end > (const char *)src))
    {
        handle_error("Chevauchement détecté dans memcpy - utilisez memmove", file, func, line);
        return NULL;
    }

    void *result = memcpy(dest, src, n);
    env.memcpy_count++;

    LOG(logger, CALL, "Fichier <%s> fonction <%s> ligne <%03d> - (appel#%03zu) - memcpy(%p, %p, %zu)",
        file, func, line, env.memcpy_count, dest, src, n);

    return result;
}

void *c_memmove(char *file, const char *func, int line, void *dest, const void *src, size_t n)
{
    memory_env_init();

    if (!validate_pointer(dest, "memmove dest", file, func, line) ||
        !validate_pointer((void *)src, "memmove src", file, func, line))
    {
        if (!validate_pointer(dest, "memmove dest", file, func, line))
        {
            handle_error("Pointeur destination invalide", file, func, line);
            return NULL;
        }

        handle_error("Pointeur source invalide", file, func, line);
        return NULL;
    }

    MemoryCell *dest_cell = find_cell_for_ptr(dest);
    MemoryCell *src_cell = find_cell_for_ptr((void *)src);

    if (!dest_cell || !dest_cell->is_allocated)
    {
        handle_error("Destination de memmove non valide", file, func, line);
        return NULL;
    }

    if (!src_cell || !src_cell->is_allocated)
    {
        handle_error("Source de memmove non valide", file, func, line);
        return NULL;
    }

    size_t dest_offset = (uintptr_t)dest - (uintptr_t)dest_cell->address;
    size_t src_offset = (uintptr_t)src - (uintptr_t)src_cell->address;

    if (n > dest_cell->block_size - dest_offset || n > src_cell->block_size - src_offset) {
        handle_error("Dépassement de buffer dans memmove", file, func, line);
        return NULL;
    }

    void *result = memmove(dest, src, n);
    env.memmove_count++;

    LOG(logger, CALL, "Fichier <%s> fonction <%s> ligne <%03d> - (appel#%03zu) - memmove(%p, %p, %zu)",
        file, func, line, env.memmove_count, dest, src, n);

    return result;
}

void c_free(char *file, const char *func, int line, void *ptr)
{
    if (!ptr)
    {
        handle_error("Tentative de libération d'un pointeur NULL", file, func, line);
        env.free_errors++;
        return;
    }

    if (!validate_pointer(ptr, "free", file, func, line))
    {
        handle_error("Pointeur invalide", file, func, line);
        env.free_errors++;
        return;
    }

    MemoryCell *cell = hashmap_get(env.allocations, ptr);
    if (!cell)
    {
        handle_error("Tentative de libération d'une adresse non allouée", file, func, line);
        env.free_errors++;
        return;
    }

    if (!cell->is_allocated)
    {
        LOG(logger, CRITICAL, "Fichier <%s> fonction %s ligne <%03d> - Double free détecté sur %p", file, func, line, ptr);
        LOG(logger, ERROR, "Première libération  : <%s:%d> %s",
            cell->file, cell->line, cell->function);
        LOG(logger, ERROR, "Tentative actuelle   : <%s:%d> %s",
            file, line, func);

        print_stack_trace(&cell->free_stack);
        env.free_errors++;
        return;
    }

    if (cell->canary != CANARY_VALUE)
    {
        LOG(logger, CRITICAL, "Corruption de mémoire détectée sur %p", ptr);
        LOG(logger, ERROR, " Allocation: <%s:%d> %s",
            cell->file, cell->line, cell->function);
        print_stack_trace(&cell->alloc_stack);
        env.free_errors++;
        return;
    }

    cell->is_allocated = false;
    cell->free_time = time(NULL);
    capture_stack(&cell->free_stack);
    env.total_freed += cell->block_size;
    env.free_count++;

    LOG(logger, INFO, "Fichier <%s> fonction <%s> ligne <%03d> - (appel#%03zu) - free(%p) -> OK",
        file, func, line, env.free_count, ptr);

    free(ptr);
    global_stats.errors.consecutive_errors = 0;
}