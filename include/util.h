/**
 * @file util.h
 * @brief Small helpers: safe string handling, terminal input, hex encoding,
 *        time formatting, paths and optional terminal colours.
 */
#ifndef LT_UTIL_H
#define LT_UTIL_H

#include <stddef.h>
#include <sys/types.h>
#include <time.h>

#include "common.h"

/** Outcome of reading one line of user input. */
typedef enum {
    INPUT_OK       =  0,
    INPUT_EOF      = -1,
    INPUT_TOO_LONG = -2
} InputResult;

/** ANSI colours (disabled automatically when stdout is not a terminal). */
typedef enum {
    CLR_RESET, CLR_BOLD, CLR_DIM, CLR_RED, CLR_GREEN, CLR_YELLOW, CLR_CYAN
} Color;

void        color_init(void);
const char *clr(Color color);

/* ---- Strings ------------------------------------------------------------ */
char  *str_trim(char *s);
int    str_copy(char *dst, size_t cap, const char *src);
int    str_is_safe_field(const char *s);
int    str_is_identifier(const char *s);
size_t str_split(char *s, char delim, char **fields, size_t max_fields);

/* ---- Terminal input ----------------------------------------------------- */
InputResult read_line(const char *prompt, char *buf, size_t cap);
InputResult read_secret(const char *prompt, char *buf, size_t cap);

/* ---- Hex encoding ------------------------------------------------------- */
void hex_encode(const unsigned char *in, size_t len, char *out);
int  hex_decode(const char *hex, unsigned char *out, size_t cap, size_t *out_len);
int  is_hex_string(const char *s, size_t expected_len);

/* ---- Time, paths, files ------------------------------------------------- */
void format_time(time_t t, char *buf, size_t cap);
void format_duration(long seconds, char *buf, size_t cap);
int  path_join(char *out, size_t cap, const char *dir, const char *name);
int  ensure_dir(const char *path, mode_t mode);
int  file_exists(const char *path);

#endif /* LT_UTIL_H */
