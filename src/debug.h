// debug.h

#ifndef DEBUG_H
#define DEBUG_H

#ifndef NDEBUG
#define debug(...) _debug(__FILE__, __LINE__, __VA_ARGS__)
#else
#define debug(...)
#endif

#ifndef NDEBUG
#include <stdarg.h>
#include <stdio.h>
#include <time.h>

#ifdef _WIN32
static inline struct tm *_localtime(time_t *t) {
    static struct tm tm;

    localtime_s(&tm, t);
    return &tm;
}
#else
static inline struct tm *_localtime(time_t *t) {
    return localtime(t);
}
#endif

static inline const char *_basename(const char *str) {
    const char *s = NULL;

    while (*str) {
        if (*str == '\\' || *str == '/') {
            s = str + 1;
        }
        str++;
    }
    return s ? s : str;
}

static inline void _debug(const char *file, int line, const char *fmt, ...) {
    struct tm *tm;
    time_t t;
    size_t n;
    va_list ap;
    char date[32];

    t = time(NULL);
    tm = _localtime(&t);
    n = strftime(date, sizeof(date), "%Y-%m-%d %H:%M:%S", tm);
    date[n] = '\0';

    fprintf(stdout, "%s %s:%d: ", date, _basename(file), line);
    va_start(ap, fmt);
    vfprintf(stdout, fmt, ap);
    va_end(ap);
    fprintf(stdout, "\n");
    fflush(stdout);
}
#endif

#endif // DEBUG_H
