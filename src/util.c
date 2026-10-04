/**
 * @file util.c
 * @brief Implementation of the general-purpose helpers declared in util.h.
 */
#include "util.h"

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <termios.h>
#include <unistd.h>

static int g_use_color = 0;

/* ------------------------------------------------------------------------ */
/* Status codes                                                             */
/* ------------------------------------------------------------------------ */

const char *status_str(Status status)
{
    switch (status) {
    case LT_OK:                return "success";
    case LT_ERR_IO:            return "file input/output error";
    case LT_ERR_MEMORY:        return "out of memory";
    case LT_ERR_FORMAT:        return "malformed data";
    case LT_ERR_EMPTY:         return "file is empty";
    case LT_ERR_NOT_FOUND:     return "not found";
    case LT_ERR_EXISTS:        return "already exists";
    case LT_ERR_INPUT:         return "invalid input";
    case LT_ERR_CRYPTO:        return "cryptographic operation failed";
    case LT_ERR_AUTH:          return "authentication failed";
    case LT_ERR_DENIED:        return "access denied";
    case LT_ERR_CHAIN_INVALID: return "blockchain failed validation";
    case LT_ERR_ON_LOAN:       return "book is already on loan";
    case LT_ERR_NOT_ON_LOAN:   return "book is not on loan";
    case LT_ERR_WRONG_MEMBER:  return "book is on loan to another member";
    case LT_ERR_INSUFFICIENT:  return "insufficient balance";
    case LT_ERR_DOUBLE_SPEND:  return "double spend";
    case LT_ERR_NONCE:         return "incorrect or reused nonce";
    case LT_ERR_POOL_EMPTY:    return "the pending pool is empty";
    }
    return "unknown error";
}

/* ------------------------------------------------------------------------ */
/* Colours                                                                  */
/* ------------------------------------------------------------------------ */

void color_init(void)
{
    const char *no_color = getenv("NO_COLOR");
    g_use_color = isatty(STDOUT_FILENO) && (no_color == NULL || no_color[0] == '\0');
}

const char *clr(Color color)
{
    static const char *const codes[] = {
        [CLR_RESET]  = "\033[0m",
        [CLR_BOLD]   = "\033[1m",
        [CLR_DIM]    = "\033[2m",
        [CLR_RED]    = "\033[31m",
        [CLR_GREEN]  = "\033[32m",
        [CLR_YELLOW] = "\033[33m",
        [CLR_CYAN]   = "\033[36m",
    };
    if (!g_use_color || (size_t)color >= sizeof codes / sizeof codes[0])
        return "";
    return codes[color];
}

/* ------------------------------------------------------------------------ */
/* Strings                                                                  */
/* ------------------------------------------------------------------------ */

/** Removes leading and trailing whitespace in place; returns the new start. */
char *str_trim(char *s)
{
    char *end;

    while (isspace((unsigned char)*s))
        s++;
    if (*s == '\0')
        return s;
    end = s + strlen(s) - 1;
    while (end > s && isspace((unsigned char)*end))
        *end-- = '\0';
    return s;
}

/**
 * Copies src into dst only if it fits completely (no silent truncation).
 * @return 0 on success, -1 if src is too long (dst is then set to "").
 */
int str_copy(char *dst, size_t cap, const char *src)
{
    size_t len = strlen(src);

    if (cap == 0)
        return -1;
    if (len >= cap) {
        dst[0] = '\0';
        return -1;
    }
    memcpy(dst, src, len + 1);
    return 0;
}

/**
 * A "safe" field contains no control characters and no '|' (the chain file
 * delimiter), so it can be stored and hashed unambiguously. UTF-8 is allowed.
 */
int str_is_safe_field(const char *s)
{
    for (; *s != '\0'; s++) {
        unsigned char c = (unsigned char)*s;
        if (c < 0x20 || c == 0x7F || c == '|')
            return 0;
    }
    return 1;
}

/** Identifiers (book / member IDs) may contain letters, digits, '-' and '_'. */
int str_is_identifier(const char *s)
{
    if (*s == '\0')
        return 0;
    for (; *s != '\0'; s++) {
        if (!isalnum((unsigned char)*s) && *s != '_' && *s != '-')
            return 0;
    }
    return 1;
}

/**
 * Splits s in place on delim. Up to max_fields pointers are stored in fields.
 * @return the total number of fields found (may exceed max_fields).
 */
size_t str_split(char *s, char delim, char **fields, size_t max_fields)
{
    size_t count = 0;
    char *p = s;

    for (;;) {
        char *sep = strchr(p, delim);
        if (count < max_fields)
            fields[count] = p;
        count++;
        if (sep == NULL)
            break;
        *sep = '\0';
        p = sep + 1;
    }
    return count;
}

/* ------------------------------------------------------------------------ */
/* Terminal input                                                           */
/* ------------------------------------------------------------------------ */

/** Reads one line without echoing it back. Handles EOF and overlong input. */
static InputResult read_line_raw(const char *prompt, char *buf, size_t cap)
{
    size_t len;

    if (prompt != NULL) {
        fputs(prompt, stdout);
        fflush(stdout);
    }
    if (cap == 0)
        return INPUT_EOF;
    if (fgets(buf, (int)cap, stdin) == NULL) {
        buf[0] = '\0';
        return INPUT_EOF;
    }
    len = strlen(buf);
    if (len > 0 && buf[len - 1] == '\n') {
        buf[--len] = '\0';
    } else if (!feof(stdin)) {
        int ch;
        while ((ch = getchar()) != '\n' && ch != EOF) {
            /* discard the rest of the overlong line */
        }
        buf[0] = '\0';
        return INPUT_TOO_LONG;
    }
    if (len > 0 && buf[len - 1] == '\r')
        buf[--len] = '\0';
    return INPUT_OK;
}

/**
 * Prompts for and reads one line. When input is piped (not a terminal) the
 * value is echoed so that saved transcripts remain readable.
 */
InputResult read_line(const char *prompt, char *buf, size_t cap)
{
    InputResult r = read_line_raw(prompt, buf, cap);

    if (r == INPUT_OK && !isatty(STDIN_FILENO))
        printf("%s\n", buf);
    return r;
}

/** Reads a password with terminal echo disabled. */
InputResult read_secret(const char *prompt, char *buf, size_t cap)
{
    struct termios old_attr, new_attr;
    InputResult r;

    if (isatty(STDIN_FILENO) && tcgetattr(STDIN_FILENO, &old_attr) == 0) {
        new_attr = old_attr;
        new_attr.c_lflag &= ~(tcflag_t)ECHO;
        /* TCSANOW (not TCSAFLUSH) so that type-ahead input is not discarded. */
        (void)tcsetattr(STDIN_FILENO, TCSANOW, &new_attr);
        r = read_line_raw(prompt, buf, cap);
        (void)tcsetattr(STDIN_FILENO, TCSANOW, &old_attr);
        putchar('\n');
    } else {
        r = read_line_raw(prompt, buf, cap);
        if (r == INPUT_OK)
            puts("********");
    }
    return r;
}

/* ------------------------------------------------------------------------ */
/* Hex encoding                                                             */
/* ------------------------------------------------------------------------ */

/** Writes 2*len lowercase hex digits plus a NUL terminator into out. */
void hex_encode(const unsigned char *in, size_t len, char *out)
{
    static const char digits[] = "0123456789abcdef";
    size_t i;

    for (i = 0; i < len; i++) {
        out[2 * i]     = digits[in[i] >> 4];
        out[2 * i + 1] = digits[in[i] & 0x0F];
    }
    out[2 * len] = '\0';
}

static int hex_value(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/** Decodes a hex string into at most cap bytes. @return 0 on success. */
int hex_decode(const char *hex, unsigned char *out, size_t cap, size_t *out_len)
{
    size_t len = strlen(hex);
    size_t i;

    if (len % 2 != 0 || len / 2 > cap)
        return -1;
    for (i = 0; i < len / 2; i++) {
        int hi = hex_value(hex[2 * i]);
        int lo = hex_value(hex[2 * i + 1]);
        if (hi < 0 || lo < 0)
            return -1;
        out[i] = (unsigned char)((hi << 4) | lo);
    }
    *out_len = len / 2;
    return 0;
}

/** True if s is exactly expected_len hexadecimal characters. */
int is_hex_string(const char *s, size_t expected_len)
{
    size_t i;

    if (strlen(s) != expected_len)
        return 0;
    for (i = 0; i < expected_len; i++) {
        if (hex_value(s[i]) < 0)
            return 0;
    }
    return 1;
}

/* ------------------------------------------------------------------------ */
/* Pseudo-random numbers (xorshift64*)                                      */
/* Used only to simulate miner hash rates; never for anything secret.       */
/* ------------------------------------------------------------------------ */

static unsigned long long g_rng_state = 0x9E3779B97F4A7C15ULL;

void rng_seed(unsigned long long seed)
{
    g_rng_state = seed ? seed : 0x9E3779B97F4A7C15ULL;
}

/** Uses $env_name as the seed if it is set (reproducible tests), else time. */
void rng_seed_from_env_or_time(const char *env_name)
{
    const char *value = getenv(env_name);

    if (value != NULL && value[0] != '\0')
        rng_seed(strtoull(value, NULL, 10));
    else
        rng_seed((unsigned long long)time(NULL) ^ ((unsigned long long)getpid() << 32));
}

static unsigned long long rng_next(void)
{
    g_rng_state ^= g_rng_state >> 12;
    g_rng_state ^= g_rng_state << 25;
    g_rng_state ^= g_rng_state >> 27;
    return g_rng_state * 0x2545F4914F6CDD1DULL;
}

unsigned long rng_range(unsigned long lo, unsigned long hi)
{
    if (hi <= lo)
        return lo;
    return lo + (unsigned long)(rng_next() % (unsigned long long)(hi - lo + 1));
}

/* ------------------------------------------------------------------------ */
/* Time, paths and files                                                    */
/* ------------------------------------------------------------------------ */

/** Monotonic clock in milliseconds (for timing proof-of-work). */
double now_ms(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1000.0 + (double)ts.tv_nsec / 1e6;
}

void format_time(time_t t, char *buf, size_t cap)
{
    struct tm tm_buf;

    if (localtime_r(&t, &tm_buf) == NULL ||
        strftime(buf, cap, "%Y-%m-%d %H:%M:%S", &tm_buf) == 0) {
        snprintf(buf, cap, "%lld", (long long)t);
    }
}

void format_duration(long seconds, char *buf, size_t cap)
{
    if (seconds % 86400 == 0)
        snprintf(buf, cap, "%ld day(s)", seconds / 86400);
    else if (seconds % 3600 == 0)
        snprintf(buf, cap, "%ld hour(s)", seconds / 3600);
    else if (seconds % 60 == 0)
        snprintf(buf, cap, "%ld minute(s)", seconds / 60);
    else
        snprintf(buf, cap, "%ld second(s)", seconds);
}

/** Builds "dir/name" into out. @return 0 on success, -1 if it does not fit. */
int path_join(char *out, size_t cap, const char *dir, const char *name)
{
    int n = snprintf(out, cap, "%s/%s", dir, name);
    return (n < 0 || (size_t)n >= cap) ? -1 : 0;
}

/** Creates a directory with the given mode unless it already exists. */
int ensure_dir(const char *path, mode_t mode)
{
    struct stat st;

    if (mkdir(path, mode) == 0)
        return 0;
    if (errno == EEXIST && stat(path, &st) == 0 && S_ISDIR(st.st_mode))
        return 0;
    return -1;
}

int file_exists(const char *path)
{
    struct stat st;
    return stat(path, &st) == 0;
}
