#ifndef LOGGER
#define LOGGER

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <time.h>

#define COLOR_RESET "\033[0m"
#define COLOR_GRAY "\033[90m"
#define COLOR_BLUE "\033[94m"
#define COLOR_YELLOW "\033[93m"
#define COLOR_RED "\033[91m"
#define COLOR_MAGENTA "\033[95m"
#define COLOR_CYAN "\033[96m"

typedef struct
{
    #ifdef LOG_TO_FILE
    bool log_to_file;
    char *file;
    #endif
} Logger;

#ifdef LOG_TO_FILE
static Logger logger = (Logger){
    .log_to_file = true,
    .file = LOG_FILE_PATH
};
#else
static Logger logger = (Logger){};
#endif

enum LOG_LEVEL
{
    INFO,
    WARNING,
    ERROR,
    CRITICAL,
    CALL
};

static const char *log_level_to_string(enum LOG_LEVEL level)
{
    switch (level)
    {
    case INFO:
        return "INFO";
    case WARNING:
        return "WARNING";
    case ERROR:
        return "ERROR";
    case CRITICAL:
        return "CRITICAL";
    case CALL:
        return "CALL";
    default:
        return "UNKNOWN";
    }
}

static const char *log_level_to_color(enum LOG_LEVEL level)
{
    switch (level)
    {
    case INFO:
        return COLOR_BLUE;
    case WARNING:
        return COLOR_YELLOW;
    case ERROR:
        return COLOR_RED;
    case CRITICAL:
        return COLOR_MAGENTA;
    case CALL:
        return COLOR_CYAN;
    default:
        return COLOR_RESET;
    }
}

static void logger_log(Logger *logger, enum LOG_LEVEL level, const char *format, ...)
{
    #ifndef LOG_TO_FILE
    (void)logger;
    #endif

    const char *level_str = log_level_to_string(level);
    const char *color = log_level_to_color(level);
    char message[1024];

    va_list args;
    va_start(args, format);
    vsnprintf(message, sizeof(message), format, args);
    va_end(args);

    time_t t = time(NULL);
    struct tm tm = *localtime(&t);

    printf("%s[%04d-%02d-%02d %02d:%02d:%02d] [%s] %s%s\n",
           color,
           tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
           tm.tm_hour, tm.tm_min, tm.tm_sec,
           level_str, message, COLOR_RESET);

    #ifdef LOG_TO_FILE
    if (logger->log_to_file && logger->file)
    {
        FILE *log_file = fopen(logger->file, "a");
        if (log_file)
        {
            fprintf(log_file, "[%04d-%02d-%02d %02d:%02d:%02d] [%s] %s\n",
                    tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
                    tm.tm_hour, tm.tm_min, tm.tm_sec,
                    level_str, message);

            fclose(log_file);
        }
    }
    #endif
}

static void logger_title(Logger *logger, const char *title)
{
    #ifndef LOG_TO_FILE
    (void)logger;
    #endif

    printf("\n────────────────────────────────────────────────────────────────\n");
    printf("            %s\n", title);
    printf("────────────────────────────────────────────────────────────────\n");

    #ifdef LOG_TO_FILE
    if (logger->log_to_file && logger->file)
    {
        FILE *log_file = fopen(logger->file, "a");
        if (log_file)
        {
            fprintf(log_file, "\n────────────────────────────────────────────────────────────────\n");
            fprintf(log_file, "            %s\n", title);
            fprintf(log_file, "────────────────────────────────────────────────────────────────\n");
            fclose(log_file);
        }
    }
    #endif
}

#define LOG(logger, level, ...) logger_log(&logger, level, __VA_ARGS__)
#define TITLE(logger, title) logger_title(&logger, title)

#endif