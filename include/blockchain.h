/* Blockchain API for creating, validating, and querying the ledger. */
#ifndef BLOCKCHAIN_H
#define BLOCKCHAIN_H

#include <openssl/evp.h>
#include "types.h"
#include "registry.h"

/* Chain lifecycle. */
int bc_init(Blockchain *chain, EVP_PKEY *key);

/* Payload serialization and hash generation for block signing. */
size_t bc_serialize_payload(const Block *b, char *buf, size_t sz);
int    bc_compute_hash(const Block *b, char out_hex[HASH_HEX_LEN]);

/* Transaction helpers. */
int bc_borrow(Blockchain *chain, const Registry *reg, EVP_PKEY *key,
              const char *book_id, const char *member_id);

int bc_return(Blockchain *chain, const Registry *reg, EVP_PKEY *key,
              const char *book_id, const char *member_id);

int bc_flag_overdue(Blockchain *chain, EVP_PKEY *key, int *flagged_out);

/* Returns the block index for an open loan, or -1 if no loan is active. */
int bc_open_loan_index(const Blockchain *chain, const char *book_id);

/* Returns the number of validation problems found. */
int bc_validate(const Blockchain *chain, EVP_PKEY *key, int verbose);

/* Output helpers for the CLI. */
void bc_print_records(const Blockchain *chain, EVP_PKEY *key);
void bc_print_block(const Block *b, EVP_PKEY *key);
void bc_print_outstanding(const Blockchain *chain);

#endif /* BLOCKCHAIN_H */
