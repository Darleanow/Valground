#ifndef M_TRACK_H
#define M_TRACK_H

#include "records.h"

#define malloc(size) c_malloc(__FILE__, __func__, __LINE__, size)
#define calloc(nmemb, size) c_calloc(__FILE__, __func__, __LINE__, nmemb, size)
#define realloc(ptr, size) c_realloc(__FILE__, __func__, __LINE__, ptr, size)
#define free(ptr) c_free(__FILE__, __func__, __LINE__, ptr)
#define memset(s, c, n) c_memset(__FILE__, __func__, __LINE__, s, c, n)
#define memcpy(dest, src, n) c_memcpy(__FILE__, __func__, __LINE__, dest, src, n)
#define memmove(dest, src, n) c_memmove(__FILE__, __func__, __LINE__, dest, src, n)

void* c_malloc(char* file, const char* func, int line, size_t size);
void* c_calloc(char* file, const char* func, int line, size_t nmemb, size_t size);
void* c_realloc(char* file, const char* func, int line, void* ptr, size_t size);
void c_free(char* file, const char* func, int line, void* ptr);
void* c_memset(char* file, const char* func, int line, void* s, int c, size_t n);
void* c_memcpy(char* file, const char* func, int line, void* dest, const void* src, size_t n);
void* c_memmove(char* file, const char* func, int line, void* dest, const void* src, size_t n);

#endif
