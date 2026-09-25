/* File persistence helpers for the on-disk ledger. */
#ifndef STORAGE_H
#define STORAGE_H

#include "types.h"

/* Save the entire ledger to chain.dat using a temp-file + rename. */
int storage_save_chain(const Blockchain *chain);

/* Read the ledger from disk into memory. */
int storage_load_chain(Blockchain *chain);

/* Corrupt one field in a sealed block to demonstrate tamper detection. */
int storage_tamper_block(Blockchain *chain, int index, int field_choice,
                         const char *new_value);

#endif /* STORAGE_H */
