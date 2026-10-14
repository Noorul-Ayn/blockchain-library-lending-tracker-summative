/**
 * @file record.c
 * @brief Lending record IDs, payloads, ECDSA signatures, hashing and parsing.
 */
#include "record.h"

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "crypto.h"
#include "util.h"

void record_clear(Record *rec)
{
    memset(rec, 0, sizeof *rec);
    tx_clear(&rec->tx);
    strcpy(rec->book_id, "-");
    strcpy(rec->copy_id, "-");
    strcpy(rec->book_title, "-");
    strcpy(rec->member_id, "-");
    strcpy(rec->member_name, "-");
    strcpy(rec->reason, "-");
    strcpy(rec->review, "-");
    strcpy(rec->signer_pubkey, "-");
    rec->condition = COND_GOOD;
}

/* ------------------------------------------------------------------------ */
/* Actions                                                                  */
/* ------------------------------------------------------------------------ */

static const struct {
    Action      action;
    const char *record_name;
    const char *request_name;
} ACTIONS[] = {
    { ACT_BORROW,   "BORROWED",  "BORROW"      },
    { ACT_RETURN,   "RETURNED",  "RETURN"      },
    { ACT_RESERVE,  "RESERVED",  "RESERVE"     },
    { ACT_RENEW,    "RENEWED",   "RENEW"       },
    { ACT_OVERDUE,  "OVERDUE",   "OVERDUE"     },
    { ACT_LOST,     "LOST",      "MARK_LOST"   },
    { ACT_TRANSFER, "TRANSFER",  "TRANSFER"    },
    { ACT_FINE,     "FINE_PAID", "SETTLE_FINE" },
};

const char *action_record_name(Action a)
{
    size_t i;

    for (i = 0; i < sizeof ACTIONS / sizeof ACTIONS[0]; i++) {
        if (ACTIONS[i].action == a)
            return ACTIONS[i].record_name;
    }
    return "NONE";
}

const char *action_request_name(Action a)
{
    size_t i;

    for (i = 0; i < sizeof ACTIONS / sizeof ACTIONS[0]; i++) {
        if (ACTIONS[i].action == a)
            return ACTIONS[i].request_name;
    }
    return "NONE";
}

int action_parse(const char *name, Action *out)
{
    size_t i;

    for (i = 0; i < sizeof ACTIONS / sizeof ACTIONS[0]; i++) {
        if (strcmp(ACTIONS[i].record_name, name) == 0) {
            *out = ACTIONS[i].action;
            return 0;
        }
    }
    return -1;
}

int action_is_lending(Action a)
{
    return a >= ACT_BORROW && a <= ACT_LOST;
}

/* ------------------------------------------------------------------------ */
/* IDs, payload, signatures, hashes                                         */
/* ------------------------------------------------------------------------ */

/*
 * The ID is the first 12 hex characters of SHA-256 over the request's key
 * fields plus 16 random bytes. The random part means two genuine requests
 * never share an ID; a re-submitted (replayed) request keeps its original
 * ID and is therefore caught as a duplicate.
 */
Status record_new_id(Record *rec)
{
    unsigned char nonce_bytes[16];
    char nonce_hex[33], text[512], digest[HASH_HEX_LEN];
    Status st = crypto_random_bytes(nonce_bytes, sizeof nonce_bytes);

    if (st != LT_OK)
        return st;
    hex_encode(nonce_bytes, sizeof nonce_bytes, nonce_hex);
    snprintf(text, sizeof text, "REQ|%s|%s|%s|%s|%s|%lld|%s", rec->signer_id, rec->member_id,
             action_record_name(rec->action), rec->book_id, rec->copy_id,
             (long long)rec->timestamp, nonce_hex);
    st = crypto_sha256_hex(text, strlen(text), digest);
    if (st == LT_OK) {
        memcpy(rec->record_id, digest, REQUEST_ID_LEN - 1);
        rec->record_id[REQUEST_ID_LEN - 1] = '\0';
    }
    return st;
}

/** Fields shared by the payload and the file form (no prefix, no signature). */
static int core_fields(const Record *rec, char *buf, size_t cap)
{
    char tx_text[TX_TEXT_MAX];
    int n;

    if (tx_serialize(&rec->tx, tx_text, sizeof tx_text) < 0)
        return -1;
    n = snprintf(buf, cap, "%s|%lld|%s|%s|%s|%s|%s|%s|%lld|%ld|%d|%s|%s|%s|%ld|%s|%s",
                 rec->record_id, (long long)rec->timestamp, action_record_name(rec->action),
                 rec->book_id, rec->copy_id, rec->book_title, rec->member_id, rec->member_name,
                 (long long)rec->due_date, rec->fine_amount, rec->token_reward,
                 condition_name(rec->condition), rec->reason, tx_text, rec->nonce,
                 rec->signer_id, rec->signer_pubkey);
    return (n < 0 || (size_t)n >= cap) ? -1 : n;
}

int record_payload(const Record *rec, char *buf, size_t cap)
{
    int n;

    if (cap < 5)
        return -1;
    memcpy(buf, "LR3|", 4);
    n = core_fields(rec, buf + 4, cap - 4);
    return n < 0 ? -1 : n + 4;
}

Status record_sign(Record *rec, EVP_PKEY *key)
{
    char *payload;
    size_t sig_len = sizeof rec->signature;
    int n;
    Status st;

    if (key == NULL)
        return LT_ERR_INPUT;
    st = crypto_public_key_hex(key, rec->signer_pubkey);
    if (st != LT_OK)
        return st;
    payload = malloc(RECORD_TEXT_MAX);
    if (payload == NULL)
        return LT_ERR_MEMORY;
    n = record_payload(rec, payload, RECORD_TEXT_MAX);
    st = n < 0 ? LT_ERR_FORMAT
               : crypto_sign(key, payload, (size_t)n, rec->signature, &sig_len);
    if (st == LT_OK)
        rec->signature_len = sig_len;
    free(payload);
    return st;
}

SigCheck record_verify(const Record *rec, KeyDirectory *dir)
{
    EVP_PKEY *embedded;
    char *payload;
    int n, ok = 0;

    if (rec->signature_len == 0 || strcmp(rec->signer_pubkey, "-") == 0)
        return SIG_MISSING;
    embedded = crypto_public_key_from_hex(rec->signer_pubkey);
    if (embedded == NULL)
        return SIG_INVALID;
    payload = malloc(RECORD_TEXT_MAX);
    if (payload != NULL) {
        n = record_payload(rec, payload, RECORD_TEXT_MAX);
        ok = n >= 0 && crypto_verify(embedded, payload, (size_t)n, rec->signature,
                                     rec->signature_len);
        free(payload);
    }
    EVP_PKEY_free(embedded);
    if (!ok)
        return SIG_INVALID;
    if (dir != NULL) {
        const PublicKeyEntry *registered = keydir_get(dir, rec->signer_id);
        if (registered == NULL || strcmp(registered->hex, rec->signer_pubkey) != 0)
            return SIG_KEY_MISMATCH;
    }
    return SIG_VALID;
}

const char *sig_check_name(SigCheck s)
{
    switch (s) {
    case SIG_VALID:        return "VALID";
    case SIG_INVALID:      return "INVALID";
    case SIG_MISSING:      return "MISSING";
    case SIG_KEY_MISMATCH: return "WRONG KEY";
    }
    return "?";
}

Status record_hash(const Record *rec, char out[HASH_HEX_LEN])
{
    char *text = malloc(RECORD_TEXT_MAX);
    char sig_hex[SIGNATURE_HEX_LEN];
    int n;
    Status st;

    if (text == NULL)
        return LT_ERR_MEMORY;
    n = record_payload(rec, text, RECORD_TEXT_MAX);
    if (rec->signature_len > 0)
        hex_encode(rec->signature, rec->signature_len, sig_hex);
    else
        strcpy(sig_hex, "-");
    if (n < 0 || (size_t)n + strlen(sig_hex) + strlen(rec->review) + 3 >= RECORD_TEXT_MAX) {
        free(text);
        return LT_ERR_FORMAT;
    }
    n += snprintf(text + n, RECORD_TEXT_MAX - (size_t)n, "|%s|%s", sig_hex, rec->review);
    st = crypto_sha256_hex(text, (size_t)n, out);
    free(text);
    return st;
}

Status record_tx_id(const Record *rec, char out[HASH_HEX_LEN])
{
    if (rec->tx.type == TX_NONE) {
        strcpy(out, "-");
        return LT_OK;
    }
    return tx_compute_id(&rec->tx, out);
}

/* ------------------------------------------------------------------------ */
/* File form                                                                */
/* ------------------------------------------------------------------------ */

int record_serialize(const Record *rec, char *buf, size_t cap)
{
    char sig_hex[SIGNATURE_HEX_LEN];
    int n = core_fields(rec, buf, cap), m;

    if (n < 0)
        return -1;
    if (rec->signature_len > 0)
        hex_encode(rec->signature, rec->signature_len, sig_hex);
    else
        strcpy(sig_hex, "-");
    m = snprintf(buf + n, cap - (size_t)n, "|%s|%s", sig_hex, rec->review);
    return (m < 0 || (size_t)m >= cap - (size_t)n) ? -1 : n + m;
}

static int id_or_dash(const char *s)
{
    return strcmp(s, "-") == 0 || str_is_identifier(s);
}

static int valid_signer_id(const char *s)
{
    if (signer_is_staff(s))
        return str_is_identifier(s + strlen(STAFF_PREFIX));
    return str_is_identifier(s);
}

Status record_parse(char **f, size_t count, Record *rec)
{
    long long ts, due;
    long fine, reward, nonce;
    char *end;
    size_t sig_len = 0;
    Status st;

    record_clear(rec);
    if (count != RECORD_FIELD_COUNT)
        return LT_ERR_FORMAT;
    if (!is_hex_string(f[0], REQUEST_ID_LEN - 1) ||
        str_copy(rec->record_id, sizeof rec->record_id, f[0]) != 0)
        return LT_ERR_FORMAT;
    ts = strtoll(f[1], &end, 10);
    if (*f[1] == '\0' || *end != '\0' || ts < 0)
        return LT_ERR_FORMAT;
    rec->timestamp = (time_t)ts;
    if (action_parse(f[2], &rec->action) != 0)
        return LT_ERR_FORMAT;
    if (!id_or_dash(f[3]) || str_copy(rec->book_id, sizeof rec->book_id, f[3]) != 0 ||
        !id_or_dash(f[4]) || str_copy(rec->copy_id, sizeof rec->copy_id, f[4]) != 0 ||
        *f[5] == '\0' || !str_is_safe_field(f[5]) ||
        str_copy(rec->book_title, sizeof rec->book_title, f[5]) != 0 ||
        !id_or_dash(f[6]) || str_copy(rec->member_id, sizeof rec->member_id, f[6]) != 0 ||
        *f[7] == '\0' || !str_is_safe_field(f[7]) ||
        str_copy(rec->member_name, sizeof rec->member_name, f[7]) != 0)
        return LT_ERR_FORMAT;
    due = strtoll(f[8], &end, 10);
    if (*f[8] == '\0' || *end != '\0' || due < 0)
        return LT_ERR_FORMAT;
    rec->due_date = (time_t)due;
    if (parse_long(f[9], 0, 1000000L, &fine) != 0 ||
        parse_long(f[10], 0, 1000L, &reward) != 0 ||
        condition_parse(f[11], &rec->condition) != 0 ||
        !id_or_dash(f[12]) || str_copy(rec->reason, sizeof rec->reason, f[12]) != 0)
        return LT_ERR_FORMAT;
    rec->fine_amount = fine;
    rec->token_reward = (int)reward;
    st = tx_parse(f[13], &rec->tx);
    if (st != LT_OK)
        return st;
    if (parse_long(f[14], 0, LONG_MAX, &nonce) != 0 || !valid_signer_id(f[15]) ||
        str_copy(rec->signer_id, sizeof rec->signer_id, f[15]) != 0)
        return LT_ERR_FORMAT;
    rec->nonce = nonce;
    if (!(strcmp(f[16], "-") == 0 || is_hex_string(f[16], PUBKEY_HEX_LEN - 1)) ||
        str_copy(rec->signer_pubkey, sizeof rec->signer_pubkey, f[16]) != 0)
        return LT_ERR_FORMAT;
    if (strcmp(f[17], "-") != 0 &&
        (hex_decode(f[17], rec->signature, sizeof rec->signature, &sig_len) != 0 || sig_len == 0))
        return LT_ERR_FORMAT;
    rec->signature_len = sig_len;
    if (*f[18] == '\0' || !str_is_safe_field(f[18]) ||
        str_copy(rec->review, sizeof rec->review, f[18]) != 0)
        return LT_ERR_FORMAT;
    return LT_OK;
}

void record_describe(const Record *rec, char *buf, size_t cap)
{
    char due[16];

    format_date(rec->due_date, due, sizeof due);
    switch (rec->action) {
    case ACT_BORROW:
        snprintf(buf, cap, "%s borrows %s, due %s", rec->member_id, rec->copy_id, due);
        break;
    case ACT_RETURN:
        if (rec->fine_amount > 0)
            snprintf(buf, cap, "%s returns %s LATE: reward %d, fine %ld", rec->member_id,
                     rec->copy_id, rec->token_reward, rec->fine_amount);
        else
            snprintf(buf, cap, "%s returns %s on time: reward %d", rec->member_id,
                     rec->copy_id, rec->token_reward);
        break;
    case ACT_RESERVE:
        snprintf(buf, cap, "%s joins the queue for %s", rec->member_id, rec->book_id);
        break;
    case ACT_RENEW:
        snprintf(buf, cap, "%s renews %s, new due %s", rec->member_id, rec->copy_id, due);
        break;
    case ACT_OVERDUE:
        snprintf(buf, cap, "%s overdue since %s, fine so far %ld", rec->copy_id, due,
                 rec->fine_amount);
        break;
    case ACT_LOST:
        snprintf(buf, cap, "%s marked LOST (%s)", rec->copy_id, rec->reason);
        break;
    case ACT_TRANSFER:
        snprintf(buf, cap, "%s -> %s, %ld coin(s) + %ld fee", rec->tx.from, rec->tx.to,
                 rec->tx.amount, rec->tx.fee);
        break;
    case ACT_FINE:
        snprintf(buf, cap, "%s pays fine of %ld (%s)", rec->member_id, rec->tx.amount,
                 rec->tx.method);
        break;
    case ACT_NONE:
        snprintf(buf, cap, "-");
        break;
    }
}
