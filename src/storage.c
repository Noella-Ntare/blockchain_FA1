/* Ledger persistence to the plain-text chain.dat file. */
#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "storage.h"
#include "crypto_utils.h"

#define TMP_FILE CHAIN_FILE ".tmp"

static void safe_copy(char *dst, size_t dst_sz, const char *src)
{
    if (dst_sz == 0) return;
    snprintf(dst, dst_sz, "%s", src ? src : "");
}

/* --------------------------------------------------------------- */
int storage_save_chain(const Blockchain *chain)
{
    FILE *fp;
    int   i;

    if (chain == NULL) return ERR_BAD_FORMAT;

    fp = fopen(TMP_FILE, "w");
    if (fp == NULL) {
        fprintf(stderr, "ERROR: cannot open '%s' for writing.\n", TMP_FILE);
        return ERR_FILE_MISSING;
    }

    fprintf(fp, "# Library Lending Blockchain ledger - do not edit by hand\n");
    fprintf(fp, "# state|index|timestamp|book_id|book_title|member_id|member_name|"
                "action|previous_hash|signature_hex|hash|reward|tx_id|nonce|"
                "attempts|difficulty|version\n");

    for (i = 0; i < chain->count; i++) {
        const Block *b = &chain->blocks[i];
        char sig_hex[SIG_HEX_LEN];

        bytes_to_hex(b->signature, b->sig_len, sig_hex);
        fprintf(fp, "B|%d|%lld|%s|%s|%s|%s|%s|%s|%s|%s|%d|%s|%llu|%llu|%d|%d\n",
            b->index, (long long)b->timestamp,
                b->book_id, b->book_title,
                b->member_id, b->member_name,
            b->action, b->previous_hash, sig_hex,
            b->hash[0] ? b->hash : "-", b->token_reward,
            b->transaction_id[0] ? b->transaction_id : "-",
            (unsigned long long)b->nonce,
            (unsigned long long)b->hash_attempts,
            b->difficulty, b->format_version);
        }
        for (i = 0; i < chain->pending_count; i++) {
        const Block *b = &chain->pending[i];
        char sig_hex[SIG_HEX_LEN];

        bytes_to_hex(b->signature, b->sig_len, sig_hex);
        fprintf(fp, "P|%d|%lld|%s|%s|%s|%s|%s|%s|%s|%s|%d|%s|%llu|%llu|%d|%d\n",
            b->index, (long long)b->timestamp,
            b->book_id, b->book_title,
            b->member_id, b->member_name,
            b->action, b->previous_hash[0] ? b->previous_hash : "-",
            sig_hex[0] ? sig_hex : "-",
            b->hash[0] ? b->hash : "-", b->token_reward,
            b->transaction_id[0] ? b->transaction_id : "-",
            (unsigned long long)b->nonce,
            (unsigned long long)b->hash_attempts,
            b->difficulty, b->format_version);
    }

    if (fclose(fp) != 0) {
        fprintf(stderr, "ERROR: failed to flush '%s'.\n", TMP_FILE);
        return ERR_FILE_MISSING;
    }

    if (rename(TMP_FILE, CHAIN_FILE) != 0) {
        fprintf(stderr, "ERROR: failed to replace '%s'.\n", CHAIN_FILE);
        return ERR_FILE_MISSING;
    }
    return OK;
}

/* --------------------------------------------------------------- */
int storage_load_chain(Blockchain *chain)
{
    FILE *fp;
    char  line[1024];
    int   lineno = 0;

    if (chain == NULL) return ERR_BAD_FORMAT;
    memset(chain, 0, sizeof(*chain));

    fp = fopen(CHAIN_FILE, "r");
    if (fp == NULL) return ERR_FILE_MISSING;      /* first run - not an error */

    while (fgets(line, sizeof(line), fp) != NULL) {
        char *f[17], *save = NULL, *tok;
        int   n = 0;
        Block *b;
        int pending = 0;

        lineno++;
        line[strcspn(line, "\r\n")] = '\0';
        if (line[0] == '#' || line[0] == '\0') continue;

        tok = strtok_r(line, "|", &save);
        while (tok != NULL && n < 17) { f[n++] = tok; tok = strtok_r(NULL, "|", &save); }

        if (n != 10 && n != 17) {
            fprintf(stderr, "ERROR: %s line %d has %d field(s), expected 10 or 17 - "
                            "ledger is corrupt.\n", CHAIN_FILE, lineno, n);
            fclose(fp);
            return ERR_BAD_FORMAT;
        }
        if (n == 17) {
            if (strcmp(f[0], "P") == 0) pending = 1;
            else if (strcmp(f[0], "B") != 0) {
                fclose(fp);
                return ERR_BAD_FORMAT;
            }
        }
        if ((!pending && chain->count >= MAX_BLOCKS) ||
            (pending && chain->pending_count >= MAX_PENDING_BLOCKS)) {
            fprintf(stderr, "ERROR: ledger contains more than %d blocks.\n",
                    pending ? MAX_PENDING_BLOCKS : MAX_BLOCKS);
            fclose(fp);
            return ERR_CAPACITY;
        }

        b = pending ? &chain->pending[chain->pending_count]
                    : &chain->blocks[chain->count];
        memset(b, 0, sizeof(*b));

        if (n == 10) {
            b->index     = atoi(f[0]);
            b->timestamp = (time_t)strtoll(f[1], NULL, 10);
            safe_copy(b->book_id,      sizeof(b->book_id),      f[2]);
            safe_copy(b->book_title,   sizeof(b->book_title),   f[3]);
            safe_copy(b->member_id,    sizeof(b->member_id),    f[4]);
            safe_copy(b->member_name,  sizeof(b->member_name),  f[5]);
            safe_copy(b->action,       sizeof(b->action),       f[6]);
            safe_copy(b->previous_hash, HASH_HEX_LEN,           f[7]);
            safe_copy(b->hash,          HASH_HEX_LEN,           f[9]);
        } else {
            b->index     = atoi(f[1]);
            b->timestamp = (time_t)strtoll(f[2], NULL, 10);
            safe_copy(b->book_id,      sizeof(b->book_id),      f[3]);
            safe_copy(b->book_title,   sizeof(b->book_title),   f[4]);
            safe_copy(b->member_id,    sizeof(b->member_id),    f[5]);
            safe_copy(b->member_name,  sizeof(b->member_name),  f[6]);
            safe_copy(b->action,       sizeof(b->action),       f[7]);
            if (strcmp(f[8], "-") != 0)
                safe_copy(b->previous_hash, HASH_HEX_LEN, f[8]);
            if (strcmp(f[10], "-") != 0)
                safe_copy(b->hash, HASH_HEX_LEN, f[10]);
            b->token_reward = atoi(f[11]);
            if (strcmp(f[12], "-") != 0)
                safe_copy(b->transaction_id, HASH_HEX_LEN, f[12]);
            b->nonce = (uint64_t)strtoull(f[13], NULL, 10);
            b->hash_attempts = (uint64_t)strtoull(f[14], NULL, 10);
            b->difficulty = atoi(f[15]);
            b->format_version = atoi(f[16]);
        }

        {
            const char *signature = n == 10 ? f[8] : f[9];
            if (strcmp(signature, "-") != 0 &&
                hex_to_bytes(signature, b->signature, SIG_MAX_LEN,
                             &b->sig_len) != OK) {
            fprintf(stderr, "ERROR: %s line %d has an unreadable signature.\n",
                    CHAIN_FILE, lineno);
            fclose(fp);
            return ERR_BAD_FORMAT;
            }
        }
        if (pending) chain->pending_count++;
        else chain->count++;
    }
    fclose(fp);

    if (chain->count == 0) {
        fprintf(stderr, "WARNING: '%s' exists but holds no blocks; a new "
                        "genesis block will be created.\n", CHAIN_FILE);
        return ERR_FILE_MISSING;
    }

        printf("[storage] Loaded %d confirmed and %d pending block(s) from %s.\n",
            chain->count, chain->pending_count, CHAIN_FILE);
    return OK;
}

/* Deliberately alter a field without re-signing to show tamper detection. */
int storage_tamper_block(Blockchain *chain, int index, int field_choice,
                         const char *new_value)
{
    Block *b;

    if (chain == NULL || index < 0 || index >= chain->count) {
        printf("ERROR: block #%d does not exist (chain holds %d block(s)).\n",
               index, chain ? chain->count : 0);
        return ERR_NOT_FOUND;
    }
    b = &chain->blocks[index];

    switch (field_choice) {
    case 1:  safe_copy(b->member_name, sizeof(b->member_name), new_value); break;
    case 2:  safe_copy(b->book_title,  sizeof(b->book_title),  new_value); break;
    case 3:  safe_copy(b->action,      sizeof(b->action),      new_value); break;
    case 4:  b->timestamp = (time_t)strtoll(new_value, NULL, 10);          break;
    default:
        printf("ERROR: unknown field selection.\n");
        return ERR_BAD_FORMAT;
    }

    /* Deliberately do NOT re-sign and do NOT recompute b->hash: this is
     * exactly what an attacker editing the ledger can do.             */
    printf("\n[tamper] Block #%d was modified in place. Its stored hash and\n"
           "         signature were left untouched, just as they would be if\n"
           "         someone edited %s directly.\n", index, CHAIN_FILE);
    return OK;
}
