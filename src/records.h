#ifndef RECORDS_H
#define RECORDS_H

#include <stddef.h>
#include <stdbool.h>
#include <time.h>
#include <stdint.h>

#define HASH_SIZE 1024
#define LOAD_FACTOR_THRESHOLD 0.75
#define STACK_TRACE_DEPTH 10
#define MAX_CONSECUTIVE_ERRORS 100

typedef struct
{
    void *frames[STACK_TRACE_DEPTH];
    int depth;
} CallStack;

typedef struct
{
    size_t error_count;
    size_t consecutive_errors;
    time_t first_error_time;
    time_t last_error_time;
    char last_error_msg[256];
} ErrorStats;

typedef struct
{
    void *address;
    size_t block_size;
    bool is_allocated;
    char *file;
    const char *function;
    int line;
    uint32_t canary;
    time_t alloc_time;
    time_t free_time;
    CallStack alloc_stack;
    CallStack free_stack;
} MemoryCell;

typedef struct HashNode
{
    void *key;
    MemoryCell value;
    struct HashNode *next;
} HashNode;

typedef struct
{
    HashNode **buckets;
    size_t size;
    size_t capacity;
} HashMap;

typedef struct
{
    HashMap *allocations;
    size_t malloc_count;
    size_t calloc_count;
    size_t realloc_count;
    size_t memset_count;
    size_t memcpy_count;
    size_t memmove_count;
    size_t free_count;
    size_t free_errors;
    size_t total_allocated;
    size_t total_freed;
    bool is_active;
} MemoryEnv;

#endif