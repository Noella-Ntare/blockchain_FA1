/* Core blockchain logic for signing, linking, and validating ledger entries. */
#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#include "blockchain.h"
#include "crypto_utils.h"

#define ZERO_HASH "0000000000000000000000000000000000000000000000000000000000000000"

/* --------------------------------------------------------------- */
static void safe_copy(char *dst, size_t dst_sz, const char *src)
{
    if (dst_sz == 0) return;
    snprintf(dst, dst_sz, "%s", src ? src : "");
}

static const char *fmt_time(time_t t)
{
    static char buf[32];
    struct tm tmv;
    localtime_r(&t, &tmv);
    strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tmv);
    return buf;
}

/* Serialize the fields that are actually signed and hashed. */
size_t bc_serialize_payload(const Block *b, char *buf, size_t sz)
{
    int n = snprintf(buf, sz, "%d|%lld|%s|%s|%s|%s|%s|%s",
                     b->index,
                     (long long)b->timestamp,
                     b->book_id,
                     b->book_title,
                     b->member_id,
                     b->member_name,
                     b->action,
                     b->previous_hash);
    if (n < 0) return 0;
    return (size_t)n < sz ? (size_t)n : sz - 1;
}

/* hash = SHA-256(payload || signature-hex) */
int bc_compute_hash(const Block *b, char out_hex[HASH_HEX_LEN])
{
    char payload[512];
    char sig_hex[SIG_HEX_LEN];
    char material[512 + SIG_HEX_LEN];
    size_t plen;

    plen = bc_serialize_payload(b, payload, sizeof(payload));
    if (plen == 0) return ERR_CRYPTO;

    bytes_to_hex(b->signature, b->sig_len, sig_hex);
    snprintf(material, sizeof(material), "%s|%s", payload, sig_hex);

    return sha256_hex(material, strlen(material), out_hex);
}

/* Sign the payload then compute the hash. */
static int seal_block(Block *b, EVP_PKEY *key)
{
    char   payload[512];
    size_t plen;

    plen = bc_serialize_payload(b, payload, sizeof(payload));
    if (plen == 0) return ERR_CRYPTO;

    if (crypto_sign(key, (const unsigned char *)payload, plen,
                    b->signature, &b->sig_len) != OK) {
        fprintf(stderr, "ERROR: failed to sign block %d.\n", b->index);
        return ERR_CRYPTO;
    }
    if (bc_compute_hash(b, b->hash) != OK) {
        fprintf(stderr, "ERROR: failed to hash block %d.\n", b->index);
        return ERR_CRYPTO;
    }
    return OK;
}

/* Create the initial ledger entry when no chain exists yet. */
int bc_init(Blockchain *chain, EVP_PKEY *key)
{
    Block *g;

    if (chain == NULL) return ERR_BAD_FORMAT;
    if (chain->count > 0) return OK;            /* already initialised */

    g = &chain->blocks[0];
    memset(g, 0, sizeof(*g));

    g->index     = 0;
    g->timestamp = time(NULL);
    safe_copy(g->book_id,      sizeof(g->book_id),      "GENESIS");
    safe_copy(g->book_title,   sizeof(g->book_title),   "Library Lending Ledger");
    safe_copy(g->member_id,    sizeof(g->member_id),    "SYSTEM");
    safe_copy(g->member_name,  sizeof(g->member_name),  "System Administrator");
    safe_copy(g->action,       sizeof(g->action),       ACTION_GENESIS);
    safe_copy(g->previous_hash, HASH_HEX_LEN,           ZERO_HASH);

    if (seal_block(g, key) != OK) return ERR_CRYPTO;

    chain->count = 1;
    printf("[chain] Genesis block created (hash %.16s...).\n", g->hash);
    return OK;
}

/* Append a signed block for a borrow/return/overdue event. */
static Block *append_block(Blockchain *chain, EVP_PKEY *key,
                           const char *book_id, const char *title,
                           const char *member_id, const char *name,
                           const char *action)
{
    Block *b;

    if (chain->count >= MAX_BLOCKS) {
        fprintf(stderr, "ERROR: chain is full (%d blocks).\n", MAX_BLOCKS);
        return NULL;
    }

    b = &chain->blocks[chain->count];
    memset(b, 0, sizeof(*b));

    b->index     = chain->count;
    b->timestamp = time(NULL);
    safe_copy(b->book_id,     sizeof(b->book_id),     book_id);
    safe_copy(b->book_title,  sizeof(b->book_title),  title);
    safe_copy(b->member_id,   sizeof(b->member_id),   member_id);
    safe_copy(b->member_name, sizeof(b->member_name), name);
    safe_copy(b->action,      sizeof(b->action),      action);
    /* copy via a local buffer: source and destination live in the same
     * array, so a direct snprintf() would be an overlapping copy      */
    {
        char prev[HASH_HEX_LEN];
        memcpy(prev, chain->blocks[chain->count - 1].hash, HASH_HEX_LEN);
        prev[HASH_HEX_LEN - 1] = '\0';
        memcpy(b->previous_hash, prev, HASH_HEX_LEN);
    }

    if (seal_block(b, key) != OK) return NULL;

    chain->count++;
    return b;
}

/* Look up the newest open loan for a given book. */
int bc_open_loan_index(const Blockchain *chain, const char *book_id)
{
    int i;
    /* walk backwards: the most recent BORROWED wins unless a RETURNED
     * for the same book appears after it.                            */
    for (i = chain->count - 1; i >= 1; i--) {
        if (strcmp(chain->blocks[i].book_id, book_id) != 0) continue;
        if (strcmp(chain->blocks[i].action, ACTION_RETURNED) == 0) return -1;
        if (strcmp(chain->blocks[i].action, ACTION_BORROWED) == 0) return i;
        /* OVERDUE does not close the loan - keep scanning backwards */
    }
    return -1;
}

/* =====================================================================
 * BORROW
 * ===================================================================== */
int bc_borrow(Blockchain *chain, const Registry *reg, EVP_PKEY *key,
              const char *book_id, const char *member_id)
{
    const Book   *bk;
    const Member *mb;
    Block        *b;
    int           open_idx;

    bk = registry_find_book(reg, book_id);
    mb = registry_find_member(reg, member_id);

    if (bk == NULL || mb == NULL) {
        printf("ERROR: Book or Member not found\n");
        if (bk == NULL) printf("       -> book_id   '%s' is not in %s\n",
                               book_id, BOOKS_FILE);
        if (mb == NULL) printf("       -> member_id '%s' is not in %s\n",
                               member_id, MEMBERS_FILE);
        return ERR_NOT_FOUND;
    }

    open_idx = bc_open_loan_index(chain, book_id);
    if (open_idx >= 0) {
        printf("ERROR: '%s' (%s) is already on loan to %s (%s) since %s.\n",
               bk->title, bk->book_id,
               chain->blocks[open_idx].member_name,
               chain->blocks[open_idx].member_id,
               fmt_time(chain->blocks[open_idx].timestamp));
        return ERR_CONFLICT;
    }

    b = append_block(chain, key, bk->book_id, bk->title,
                     mb->member_id, mb->full_name, ACTION_BORROWED);
    if (b == NULL) return ERR_CRYPTO;

    printf("\nSUCCESS: Block #%d appended - BORROWED\n", b->index);
    bc_print_block(b, key);
    return OK;
}

/* =====================================================================
 * RETURN
 * ===================================================================== */
int bc_return(Blockchain *chain, const Registry *reg, EVP_PKEY *key,
              const char *book_id, const char *member_id)
{
    const Book   *bk;
    const Member *mb;
    Block        *b;
    int           open_idx;

    bk = registry_find_book(reg, book_id);
    mb = registry_find_member(reg, member_id);

    if (bk == NULL || mb == NULL) {
        printf("ERROR: Book or Member not found\n");
        if (bk == NULL) printf("       -> book_id   '%s' is not in %s\n",
                               book_id, BOOKS_FILE);
        if (mb == NULL) printf("       -> member_id '%s' is not in %s\n",
                               member_id, MEMBERS_FILE);
        return ERR_NOT_FOUND;
    }

    open_idx = bc_open_loan_index(chain, book_id);
    if (open_idx < 0) {
        printf("ERROR: No open loan found for '%s' (%s). The book was never "
               "borrowed or has already been returned.\n",
               bk->title, bk->book_id);
        return ERR_CONFLICT;
    }

    if (strcmp(chain->blocks[open_idx].member_id, mb->member_id) != 0) {
        printf("ERROR: '%s' is on loan to %s (%s), not to %s (%s).\n",
               bk->title,
               chain->blocks[open_idx].member_name,
               chain->blocks[open_idx].member_id,
               mb->full_name, mb->member_id);
        return ERR_CONFLICT;
    }

    b = append_block(chain, key, bk->book_id, bk->title,
                     mb->member_id, mb->full_name, ACTION_RETURNED);
    if (b == NULL) return ERR_CRYPTO;

    printf("\nSUCCESS: Block #%d appended - RETURNED "
           "(loan opened in block #%d, held for %.0f day(s))\n",
           b->index, open_idx,
           difftime(b->timestamp, chain->blocks[open_idx].timestamp) / 86400.0);
    bc_print_block(b, key);
    return OK;
}

/* =====================================================================
 * OVERDUE sweep - appends an OVERDUE block for every loan older than
 * LOAN_PERIOD_DAYS that has not already been flagged.
 * ===================================================================== */
static int already_flagged(const Blockchain *chain, int loan_idx)
{
    int i;
    for (i = loan_idx + 1; i < chain->count; i++)
        if (strcmp(chain->blocks[i].book_id,
                   chain->blocks[loan_idx].book_id) == 0 &&
            strcmp(chain->blocks[i].action, ACTION_OVERDUE) == 0)
            return 1;
    return 0;
}

int bc_flag_overdue(Blockchain *chain, EVP_PKEY *key, int *flagged_out)
{
    time_t now = time(NULL);
    int    i, flagged = 0;
    int    snapshot = chain->count;   /* do not re-scan blocks we append */

    for (i = 1; i < snapshot; i++) {
        const Block *loan = &chain->blocks[i];
        double days;

        if (strcmp(loan->action, ACTION_BORROWED) != 0) continue;
        if (bc_open_loan_index(chain, loan->book_id) != i) continue; /* closed */
        if (already_flagged(chain, i)) continue;

        days = difftime(now, loan->timestamp) / 86400.0;
        if (days <= (double)LOAN_PERIOD_DAYS) continue;

        if (append_block(chain, key, loan->book_id, loan->book_title,
                         loan->member_id, loan->member_name,
                         ACTION_OVERDUE) == NULL)
            return ERR_CRYPTO;

        printf("  OVERDUE: '%s' held by %s for %.0f days "
               "(limit %d) -> block #%d\n",
               loan->book_title, loan->member_name, days,
               LOAN_PERIOD_DAYS, chain->count - 1);
        flagged++;
    }

    if (flagged_out) *flagged_out = flagged;
    if (flagged == 0)
        printf("  No overdue loans. All active loans are within the %d-day "
               "limit.\n", LOAN_PERIOD_DAYS);
    return OK;
}

/* =====================================================================
 * VALIDATION
 * ===================================================================== */
int bc_validate(const Blockchain *chain, EVP_PKEY *key, int verbose)
{
    int  i, problems = 0;
    char recomputed[HASH_HEX_LEN];

    if (chain == NULL || chain->count == 0) {
        printf("ERROR: the chain is empty - nothing to validate.\n");
        return 1;
    }

    if (verbose) {
        printf("\n==================== CHAIN VALIDATION "
               "====================\n");
        printf("Blocks to verify: %d\n\n", chain->count);
    }

    /* --- genesis-specific checks ---------------------------------- */
    if (chain->blocks[0].index != 0 ||
        strcmp(chain->blocks[0].previous_hash, ZERO_HASH) != 0) {
        printf("  [FAIL] Block 0 is not a well-formed genesis block "
               "(previous_hash must be 64 zeros).\n");
        problems++;
    }

    for (i = 0; i < chain->count; i++) {
        const Block *b = &chain->blocks[i];
        char  payload[512];
        size_t plen;
        int   hash_ok, link_ok = 1, sig_ok, idx_ok;

        /* (a) index sequence */
        idx_ok = (b->index == i);

        /* (b) stored hash must match a fresh recomputation */
        bc_compute_hash(b, recomputed);
        hash_ok = (strcmp(recomputed, b->hash) == 0);

        /* (c) linkage to the preceding block */
        if (i > 0)
            link_ok = (strcmp(b->previous_hash,
                              chain->blocks[i - 1].hash) == 0);

        /* (d) digital signature over the payload */
        plen   = bc_serialize_payload(b, payload, sizeof(payload));
        sig_ok = crypto_verify(key, (const unsigned char *)payload, plen,
                               b->signature, b->sig_len) == 1;

        if (idx_ok && hash_ok && link_ok && sig_ok) {
            if (verbose)
                printf("  [ OK ] Block %-3d %-8s %-10s hash=%.16s... "
                       "link OK  sig OK\n",
                       b->index, b->action, b->book_id, b->hash);
            continue;
        }

        problems++;
        printf("  [FAIL] Block %d (%s / %s)\n", b->index, b->book_id,
               b->action);
        if (!idx_ok)
            printf("         - index field (%d) does not match its position "
                   "(%d)\n", b->index, i);
        if (!hash_ok) {
            printf("         - stored hash   : %s\n", b->hash);
            printf("         - recomputed    : %s\n", recomputed);
            printf("         - the block's contents were modified after "
                   "it was sealed\n");
        }
        if (!link_ok) {
            printf("         - previous_hash : %s\n", b->previous_hash);
            printf("         - block %d hash  : %s\n", i - 1,
                   chain->blocks[i - 1].hash);
            printf("         - the link to the preceding block is broken\n");
        }
        if (!sig_ok)
            printf("         - ECDSA signature does NOT verify against the "
                   "librarian public key\n");
    }

    if (verbose) {
        printf("\n-----------------------------------------------------"
               "------\n");
        if (problems == 0)
            printf("RESULT: CHAIN VALID - all %d block(s) are intact, linked "
                   "and correctly signed.\n", chain->count);
        else
            printf("RESULT: CHAIN INVALID - %d problem(s) detected. "
                   "The ledger has been tampered with.\n", problems);
        printf("==========================================================="
               "\n");
    }
    return problems;
}

/* =====================================================================
 * Printing
 * ===================================================================== */
void bc_print_block(const Block *b, EVP_PKEY *key)
{
    char payload[512], sig_hex[SIG_HEX_LEN];
    size_t plen;
    int sig_ok;

    plen   = bc_serialize_payload(b, payload, sizeof(payload));
    sig_ok = crypto_verify(key, (const unsigned char *)payload, plen,
                           b->signature, b->sig_len) == 1;
    bytes_to_hex(b->signature, b->sig_len, sig_hex);

    printf("  ---------------------------------------------------------\n");
    printf("   index         : %d\n", b->index);
    printf("   timestamp     : %lld  (%s)\n", (long long)b->timestamp,
           fmt_time(b->timestamp));
    printf("   book          : %s - %s\n", b->book_id, b->book_title);
    printf("   member        : %s - %s\n", b->member_id, b->member_name);
    printf("   action        : %s\n", b->action);
    printf("   previous_hash : %s\n", b->previous_hash);
    printf("   signature     : %.32s... (%zu bytes DER, %s)\n",
           sig_hex, b->sig_len, sig_ok ? "VALID" : "INVALID");
    printf("   hash          : %s\n", b->hash);
    printf("  ---------------------------------------------------------\n");
}

void bc_print_records(const Blockchain *chain, EVP_PKEY *key)
{
    int i;

    printf("\n===================== LENDING RECORDS "
           "=====================\n");
    printf("%-4s %-19s %-9s %-9s %-24s %-20s %-6s\n",
           "#", "TIMESTAMP", "BOOK", "MEMBER", "TITLE", "NAME", "SIG");
    printf("--------------------------------------------------------------"
           "--------------------------------\n");

    for (i = 0; i < chain->count; i++) {
        const Block *b = &chain->blocks[i];
        char payload[512];
        size_t plen;
        int sig_ok;

        plen   = bc_serialize_payload(b, payload, sizeof(payload));
        sig_ok = crypto_verify(key, (const unsigned char *)payload, plen,
                               b->signature, b->sig_len) == 1;

        printf("%-4d %-19s %-9s %-9s %-24.24s %-20.20s %-6s\n",
               b->index, fmt_time(b->timestamp), b->book_id, b->member_id,
               b->book_title, b->member_name, sig_ok ? "OK" : "BAD");
        printf("     action: %-9s  prev: %.16s...  hash: %.16s...\n",
               b->action, b->previous_hash, b->hash);
    }
    printf("--------------------------------------------------------------"
           "--------------------------------\n");
    printf("%d block(s) in the chain (block 0 is the genesis block).\n",
           chain->count);
}

void bc_print_outstanding(const Blockchain *chain)
{
    int i, n = 0;
    time_t now = time(NULL);

    printf("\n================== BOOKS CURRENTLY ON LOAN "
           "==================\n");
    for (i = 1; i < chain->count; i++) {
        const Block *b = &chain->blocks[i];
        double days;

        if (strcmp(b->action, ACTION_BORROWED) != 0) continue;
        if (bc_open_loan_index(chain, b->book_id) != i) continue;

        days = difftime(now, b->timestamp) / 86400.0;
        printf("  %-8s %-30.30s -> %-20.20s (%s, %.1f day(s)%s)\n",
               b->book_id, b->book_title, b->member_name,
               b->member_id, days,
               days > LOAN_PERIOD_DAYS ? ", OVERDUE" : "");
        n++;
    }
    if (n == 0) printf("  No books are currently on loan.\n");
    printf("============================================================\n");
}
