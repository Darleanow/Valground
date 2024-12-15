#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include "records.h"
#include "m_track.h"

#define RED "\x1b[31m"
#define GREEN "\x1b[32m"
#define YELLOW "\x1b[33m"
#define BLUE "\x1b[34m"
#define RESET "\x1b[0m"

typedef struct
{
    int total;
    int passed;
    int failed;
    int skipped;
} TestResults;

typedef struct
{
    const char *name;
    void (*func)(void);
    bool enabled;
} TestCase;

TestResults results = {0};
static MemoryEnv *test_env = NULL;

#define ASSERT_TRUE(x)                                                                              \
    do                                                                                              \
    {                                                                                               \
        if (!(x))                                                                                   \
        {                                                                                           \
            printf(RED "ÉCHEC" RESET " - %s:%d - Assertion échouée: %s\n", __FILE__, __LINE__, #x); \
            results.failed++;                                                                       \
            return;                                                                                 \
        }                                                                                           \
    } while (0)

#define ASSERT_FALSE(x) ASSERT_TRUE(!(x))

#define ASSERT_NULL(x) ASSERT_TRUE((x) == NULL)
#define ASSERT_NOT_NULL(x) ASSERT_TRUE((x) != NULL)

#define ASSERT_EQ(x, y)                                                        \
    do                                                                         \
    {                                                                          \
        if ((x) != (y))                                                        \
        {                                                                      \
            printf(RED "ÉCHEC" RESET " - %s:%d - Attendu: %ld, Obtenu: %ld\n", \
                   __FILE__, __LINE__, (long)(y), (long)(x));                  \
            results.failed++;                                                  \
            return;                                                            \
        }                                                                      \
    } while (0)

void test_malloc_basic(void)
{
    void *ptr = c_malloc(__FILE__, __func__, __LINE__, 100);
    ASSERT_NOT_NULL(ptr);
    c_free(__FILE__, __func__, __LINE__, ptr);
}

void test_malloc_zero(void)
{
    void *ptr = c_malloc(__FILE__, __func__, __LINE__, 0);
    ASSERT_NULL(ptr);
}

void test_malloc_huge(void)
{
    void *ptr = c_malloc(__FILE__, __func__, __LINE__, SIZE_MAX);
    ASSERT_NULL(ptr);
}

void test_calloc_basic(void)
{
    int *ptr = c_calloc(__FILE__, __func__, __LINE__, 5, sizeof(int));
    ASSERT_NOT_NULL(ptr);
    for (int i = 0; i < 5; i++)
    {
        ASSERT_EQ(ptr[i], 0);
    }
    c_free(__FILE__, __func__, __LINE__, ptr);
}

void test_calloc_overflow(void)
{
    void *ptr = c_calloc(__FILE__, __func__, __LINE__, SIZE_MAX, SIZE_MAX);
    ASSERT_NULL(ptr);
}

void test_realloc_growth(void)
{
    char *ptr = c_malloc(__FILE__, __func__, __LINE__, 10);
    ASSERT_NOT_NULL(ptr);
    memset(ptr, 'A', 9);
    ptr[9] = '\0';

    ptr = c_realloc(__FILE__, __func__, __LINE__, ptr, 20);
    ASSERT_NOT_NULL(ptr);
    ASSERT_EQ(ptr[0], 'A');
    ASSERT_EQ(ptr[8], 'A');

    c_free(__FILE__, __func__, __LINE__, ptr);
}

void test_realloc_shrink(void)
{
    char *ptr = c_malloc(__FILE__, __func__, __LINE__, 100);
    ASSERT_NOT_NULL(ptr);
    ptr = c_realloc(__FILE__, __func__, __LINE__, ptr, 50);
    ASSERT_NOT_NULL(ptr);
    c_free(__FILE__, __func__, __LINE__, ptr);
}

void test_realloc_null(void)
{
    void *ptr = c_realloc(__FILE__, __func__, __LINE__, NULL, 100);
    ASSERT_NOT_NULL(ptr);
    c_free(__FILE__, __func__, __LINE__, ptr);
}

void test_memset_full(void)
{
    char *ptr = c_malloc(__FILE__, __func__, __LINE__, 100);
    ASSERT_NOT_NULL(ptr);

    void *result = c_memset(__FILE__, __func__, __LINE__, ptr, 'X', 100);
    ASSERT_NOT_NULL(result);
    ASSERT_EQ(result, ptr);

    for (int i = 0; i < 100; i++)
    {
        ASSERT_EQ(ptr[i], 'X');
    }

    c_free(__FILE__, __func__, __LINE__, ptr);
}

void test_memset_overflow(void)
{
    char *ptr = c_malloc(__FILE__, __func__, __LINE__, 100);
    ASSERT_NOT_NULL(ptr);

    void *result = c_memset(__FILE__, __func__, __LINE__, ptr, 'X', 101);
    ASSERT_NULL(result);

    c_free(__FILE__, __func__, __LINE__, ptr);
}

void test_memcpy_basic(void)
{
    char *src = c_malloc(__FILE__, __func__, __LINE__, 100);
    char *dest = c_malloc(__FILE__, __func__, __LINE__, 100);
    ASSERT_NOT_NULL(src);
    ASSERT_NOT_NULL(dest);

    memset(src, 'A', 100);
    void *result = c_memcpy(__FILE__, __func__, __LINE__, dest, src, 100);
    ASSERT_NOT_NULL(result);
    ASSERT_EQ(result, dest);

    for (int i = 0; i < 100; i++)
    {
        ASSERT_EQ(dest[i], 'A');
    }

    c_free(__FILE__, __func__, __LINE__, src);
    c_free(__FILE__, __func__, __LINE__, dest);
}

void test_memcpy_overlap(void)
{
    char *ptr = c_malloc(__FILE__, __func__, __LINE__, 100);
    ASSERT_NOT_NULL(ptr);
    memset(ptr, 'A', 100);

    void *result = c_memcpy(__FILE__, __func__, __LINE__, ptr + 10, ptr, 50);
    ASSERT_NULL(result);

    c_free(__FILE__, __func__, __LINE__, ptr);
}

void test_memmove_basic(void)
{
    char *ptr = c_malloc(__FILE__, __func__, __LINE__, 100);
    ASSERT_NOT_NULL(ptr);
    memset(ptr, 'B', 100);

    void *result = c_memmove(__FILE__, __func__, __LINE__, ptr + 10, ptr, 50);
    ASSERT_NOT_NULL(result);
    ASSERT_EQ(result, ptr + 10);

    c_free(__FILE__, __func__, __LINE__, ptr);
}

void test_free_null(void)
{
    c_free(__FILE__, __func__, __LINE__, NULL);
}

void test_double_free(void)
{
    void *ptr = c_malloc(__FILE__, __func__, __LINE__, 10);
    ASSERT_NOT_NULL(ptr);

    c_free(__FILE__, __func__, __LINE__, ptr);
    c_free(__FILE__, __func__, __LINE__, ptr);
}

void test_free_unaligned(void)
{
    char *ptr = c_malloc(__FILE__, __func__, __LINE__, 100);
    ASSERT_NOT_NULL(ptr);

    void *unaligned = (void *)((uintptr_t)ptr + 1);
    c_free(__FILE__, __func__, __LINE__, unaligned);

    c_free(__FILE__, __func__, __LINE__, ptr);
}

void test_stress_allocation(void)
{
#define ALLOC_COUNT 1000
    void *ptrs[ALLOC_COUNT];

    for (int i = 0; i < ALLOC_COUNT; i++)
    {
        ptrs[i] = c_malloc(__FILE__, __func__, __LINE__, (i % 100) + 1);
        ASSERT_NOT_NULL(ptrs[i]);
    }

    for (int i = 0; i < ALLOC_COUNT; i += 2)
    {
        c_free(__FILE__, __func__, __LINE__, ptrs[i]);
        ptrs[i] = NULL;
    }

    for (int i = 0; i < ALLOC_COUNT; i += 2)
    {
        ptrs[i] = c_malloc(__FILE__, __func__, __LINE__, (i % 100) + 1);
        ASSERT_NOT_NULL(ptrs[i]);
    }

    for (int i = 0; i < ALLOC_COUNT; i++)
    {
        if (ptrs[i])
        {
            c_free(__FILE__, __func__, __LINE__, ptrs[i]);
        }
    }
}

void test_stress_realloc(void)
{
    void *ptr = c_malloc(__FILE__, __func__, __LINE__, 1);
    ASSERT_NOT_NULL(ptr);

    for (int i = 2; i <= 1000; i++)
    {
        ptr = c_realloc(__FILE__, __func__, __LINE__, ptr, i);
        ASSERT_NOT_NULL(ptr);
    }

    c_free(__FILE__, __func__, __LINE__, ptr);
}

void test_memory_leak(void)
{
    void *ptr1 = c_malloc(__FILE__, __func__, __LINE__, 100);
    void *ptr2 = c_malloc(__FILE__, __func__, __LINE__, 200);
    void *ptr3 = c_malloc(__FILE__, __func__, __LINE__, 300);

    ASSERT_NOT_NULL(ptr1);
    ASSERT_NOT_NULL(ptr2);
    ASSERT_NOT_NULL(ptr3);

    c_free(__FILE__, __func__, __LINE__, ptr1);
}

TestCase test_cases[] = {
    {"Test malloc basique", test_malloc_basic, true},
    {"Test malloc taille zéro", test_malloc_zero, true},
    {"Test malloc taille énorme", test_malloc_huge, true},
    {"Test calloc basique", test_calloc_basic, true},
    {"Test calloc overflow", test_calloc_overflow, true},
    {"Test realloc croissance", test_realloc_growth, true},
    {"Test realloc réduction", test_realloc_shrink, true},
    {"Test realloc NULL", test_realloc_null, true},
    {"Test memset complet", test_memset_full, true},
    {"Test memset overflow", test_memset_overflow, true},
    {"Test memcpy basique", test_memcpy_basic, true},
    {"Test memcpy chevauchement", test_memcpy_overlap, true},
    {"Test memmove basique", test_memmove_basic, true},
    {"Test free NULL", test_free_null, true},
    {"Test double free", test_double_free, true},
    {"Test free non aligné", test_free_unaligned, true},
    {"Test stress allocations", test_stress_allocation, true},
    {"Test stress realloc", test_stress_realloc, true},
    {"Test fuites mémoire", test_memory_leak, true},
    {NULL, NULL, false}};

void run_all_tests(void)
{
    printf(BLUE "\n=== Démarrage des tests unitaires ===\n\n" RESET);

    for (int i = 0; test_cases[i].name != NULL; i++)
    {
        if (!test_cases[i].enabled)
        {
            printf(YELLOW "SKIP" RESET " - %s\n", test_cases[i].name);
            results.skipped++;
            continue;
        }

        printf("Test: %s\n", test_cases[i].name);
        results.total++;

        int failed_before = results.failed;
        test_cases[i].func();
        if (results.failed == failed_before)
        {
            printf(GREEN "OK" RESET " - %s\n\n", test_cases[i].name);
            results.passed++;
        }
    }
}

void log_results(void)
{
    printf(BLUE "\n=== Résultats des tests ===\n" RESET);
    printf("Total: %d\n", results.total);
    printf(GREEN "Réussis: %d\n" RESET, results.passed);
    printf(RED "Échoués: %d\n" RESET, results.failed);
    printf(YELLOW "Ignorés: %d\n" RESET, results.skipped);
}

int main(void)
{
    atexit(log_results);
    run_all_tests();
    return results.failed > 0 ? 1 : 0;
}