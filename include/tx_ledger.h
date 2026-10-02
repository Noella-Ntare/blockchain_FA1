#ifndef TX_LEDGER_H
#define TX_LEDGER_H

#include "types.h"

#define TX_FEE 1
#define MAX_UTXO_OUTPUTS 8192

typedef enum {
    TX_MODEL_UTXO = 1,
    TX_MODEL_ACCOUNT = 2
} TxModel;

typedef struct TxHistoryEntry {
    char sender[20];
    char recipient[20];
    double amount;
    double fee;
    uint64_t nonce;
    struct TxHistoryEntry *next;
} TxHistoryEntry;

typedef struct {
    char member_id[20];
    char member_name[50];
    double balance;
    uint64_t nonce;
    TxHistoryEntry *history_head;
    TxHistoryEntry *history_tail;
} TxAccount;

typedef struct {
    char transaction_id[HASH_HEX_LEN];
    unsigned int output_index;
    char owner[20];
    double amount;
    int spent;
} UTXO;

typedef struct {
    TxModel model;
    TxAccount accounts[MAX_MEMBERS];
    int account_count;
    UTXO outputs[MAX_UTXO_OUTPUTS];
    int output_count;
    uint64_t transaction_counter;
} TokenLedger;

int tx_ledger_init(TokenLedger *ledger, const Registry *reg,
                   const Blockchain *chain, TxModel model);
void tx_ledger_free(TokenLedger *ledger);
int tx_confirm_block(TokenLedger *ledger, const Block *block);
int tx_mining_credit(TokenLedger *ledger, const char *member_id,
                     const char *transaction_id, unsigned int output_index,
                     double amount);
int tx_transfer(TokenLedger *ledger, const char *sender_id,
                const char *recipient_id, int amount, uint64_t nonce);
void tx_print_balances(const TokenLedger *ledger);
void tx_print_utxos(const TokenLedger *ledger);
void tx_print_history(const TokenLedger *ledger, const char *member_id);

#endif