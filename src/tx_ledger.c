#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "crypto_utils.h"
#include "tx_ledger.h"

static TxAccount *find_account(TokenLedger *ledger, const char *member_id)
{
    int i;
    for (i = 0; i < ledger->account_count; i++)
        if (strcmp(ledger->accounts[i].member_id, member_id) == 0)
            return &ledger->accounts[i];
    return NULL;
}

static const TxAccount *find_account_const(const TokenLedger *ledger,
                                           const char *member_id)
{
    int i;
    for (i = 0; i < ledger->account_count; i++)
        if (strcmp(ledger->accounts[i].member_id, member_id) == 0)
            return &ledger->accounts[i];
    return NULL;
}

static void append_history(TokenLedger *ledger, const char *sender,
                           const char *recipient, double amount, double fee,
                           uint64_t nonce)
{
    int i;
    for (i = 0; i < ledger->account_count; i++) {
        TxAccount *account = &ledger->accounts[i];
        TxHistoryEntry *entry;
        if (strcmp(account->member_id, sender) != 0 &&
            strcmp(account->member_id, recipient) != 0) continue;
        entry = calloc(1, sizeof(*entry));
        if (entry == NULL) return;
        snprintf(entry->sender, sizeof(entry->sender), "%s", sender);
        snprintf(entry->recipient, sizeof(entry->recipient), "%s", recipient);
        entry->amount = amount;
        entry->fee = fee;
        entry->nonce = nonce;
        if (account->history_tail != NULL) account->history_tail->next = entry;
        else account->history_head = entry;
        account->history_tail = entry;
    }
}

static double utxo_balance(const TokenLedger *ledger, const char *member_id)
{
    double total = 0.0;
    int i;
    for (i = 0; i < ledger->output_count; i++)
        if (!ledger->outputs[i].spent &&
            strcmp(ledger->outputs[i].owner, member_id) == 0)
            total += ledger->outputs[i].amount;
    return total;
}

static int add_output(TokenLedger *ledger, const char *txid,
                      unsigned int output_index, const char *owner, double amount)
{
    UTXO *output;
    if (ledger->output_count >= MAX_UTXO_OUTPUTS) return ERR_CAPACITY;
    output = &ledger->outputs[ledger->output_count++];
    memset(output, 0, sizeof(*output));
    snprintf(output->transaction_id, sizeof(output->transaction_id), "%s", txid);
    output->output_index = output_index;
    snprintf(output->owner, sizeof(output->owner), "%s", owner);
    output->amount = amount;
    return OK;
}

int tx_mining_credit(TokenLedger *ledger, const char *member_id,
                     const char *transaction_id, unsigned int output_index,
                     double amount)
{
    TxAccount *account;
    if (ledger == NULL || member_id == NULL || transaction_id == NULL ||
        amount <= 0.0) return ERR_BAD_FORMAT;
    account = find_account(ledger, member_id);
    if (account == NULL) return ERR_NOT_FOUND;
    if (ledger->model == TX_MODEL_ACCOUNT) {
        account->balance += amount;
    } else if (add_output(ledger, transaction_id, output_index,
                          member_id, amount) != OK) {
        return ERR_CAPACITY;
    }
    append_history(ledger, "MINING", member_id, amount, 0.0, 0);
    return OK;
}

int tx_confirm_block(TokenLedger *ledger, const Block *block)
{
    TxAccount *recipient;
    double net;

    if (ledger == NULL || block == NULL ||
        strcmp(block->action, ACTION_RETURNED) != 0 ||
        block->token_reward <= 0) return OK;
    recipient = find_account(ledger, block->member_id);
    if (recipient == NULL || block->token_reward <= TX_FEE ||
        block->transaction_id[0] == '\0') return ERR_BAD_FORMAT;
    net = block->token_reward - TX_FEE;

    if (ledger->model == TX_MODEL_ACCOUNT) {
        recipient->balance += net;
    } else {
        if (ledger->output_count > MAX_UTXO_OUTPUTS - 2)
            return ERR_CAPACITY;
        if (add_output(ledger, block->transaction_id, 0,
                       block->member_id, net) != OK ||
            add_output(ledger, block->transaction_id, 1,
                       "SYSTEM", TX_FEE) != OK) return ERR_CAPACITY;
    }
    append_history(ledger, "SYSTEM", block->member_id,
                   block->token_reward, TX_FEE, 0);
    return OK;
}

int tx_ledger_init(TokenLedger *ledger, const Registry *reg,
                   const Blockchain *chain, TxModel model)
{
    int i;
    if (ledger == NULL || reg == NULL || chain == NULL ||
        (model != TX_MODEL_UTXO && model != TX_MODEL_ACCOUNT))
        return ERR_BAD_FORMAT;
    memset(ledger, 0, sizeof(*ledger));
    ledger->model = model;
    ledger->account_count = reg->member_count;
    for (i = 0; i < reg->member_count; i++) {
        snprintf(ledger->accounts[i].member_id,
                 sizeof(ledger->accounts[i].member_id), "%s",
                 reg->members[i].member_id);
        snprintf(ledger->accounts[i].member_name,
                 sizeof(ledger->accounts[i].member_name), "%s",
                 reg->members[i].full_name);
    }
    for (i = 0; i < chain->count; i++)
        if (tx_confirm_block(ledger, &chain->blocks[i]) != OK) {
            tx_ledger_free(ledger);
            return ERR_CAPACITY;
        }
    return OK;
}

void tx_ledger_free(TokenLedger *ledger)
{
    int i;
    if (ledger == NULL) return;
    for (i = 0; i < ledger->account_count; i++) {
        TxHistoryEntry *entry = ledger->accounts[i].history_head;
        while (entry != NULL) {
            TxHistoryEntry *next = entry->next;
            free(entry);
            entry = next;
        }
        ledger->accounts[i].history_head = NULL;
        ledger->accounts[i].history_tail = NULL;
    }
}

int tx_transfer(TokenLedger *ledger, const char *sender_id,
                const char *recipient_id, int amount, uint64_t nonce)
{
    TxAccount *sender, *recipient;
    int i, selected_count = 0, required_outputs = 0;
    double selected_total = 0.0;
    char material[256], txid[HASH_HEX_LEN];

    if (ledger == NULL || amount <= 0) return ERR_BAD_FORMAT;
    sender = find_account(ledger, sender_id);
    recipient = find_account(ledger, recipient_id);
    if (sender == NULL || recipient == NULL) {
        printf("ERROR: sender and recipient must be registered member IDs.\n");
        return ERR_NOT_FOUND;
    }
    if (ledger->model == TX_MODEL_ACCOUNT && nonce != sender->nonce + 1) {
        printf("ERROR: nonce rejected for %s; expected %llu, received %llu.\n",
               sender_id, (unsigned long long)(sender->nonce + 1),
               (unsigned long long)nonce);
        return ERR_CONFLICT;
    }

    if (ledger->model == TX_MODEL_ACCOUNT) {
        if (sender->balance < (double)amount + TX_FEE) {
            printf("ERROR: insufficient balance; need %d amount + %d fee.\n",
                   amount, TX_FEE);
            return ERR_CONFLICT;
        }
    } else {
        if (utxo_balance(ledger, sender_id) < (double)amount + TX_FEE) {
            printf("ERROR: insufficient unspent outputs; need %d amount + %d fee.\n",
                   amount, TX_FEE);
            return ERR_CONFLICT;
        }
        for (i = 0; i < ledger->output_count &&
                    selected_total < amount + TX_FEE; i++) {
            UTXO *output = &ledger->outputs[i];
            if (output->spent || strcmp(output->owner, sender_id) != 0) continue;
            selected_total += output->amount;
            selected_count++;
        }
        required_outputs = 2 +
            (selected_total > amount + TX_FEE ? 1 : 0);
        if (ledger->output_count > MAX_UTXO_OUTPUTS - required_outputs)
            return ERR_CAPACITY;
    }

    snprintf(material, sizeof(material), "%s|%s|%d|%llu|%llu",
             sender_id, recipient_id, amount, (unsigned long long)nonce,
             (unsigned long long)++ledger->transaction_counter);
    if (sha256_hex(material, strlen(material), txid) != OK) return ERR_CRYPTO;

    if (ledger->model == TX_MODEL_ACCOUNT) {
        sender->balance -= (double)amount + TX_FEE;
        recipient->balance += amount;
        sender->nonce++;
        append_history(ledger, sender_id, recipient_id, amount, TX_FEE,
                       sender->nonce);
    } else {
        int remaining = selected_count;
        double change = selected_total - amount - TX_FEE;
        for (i = 0; i < ledger->output_count && remaining > 0; i++) {
            UTXO *output = &ledger->outputs[i];
            if (output->spent || strcmp(output->owner, sender_id) != 0) continue;
            output->spent = 1;
            remaining--;
        }
        if (add_output(ledger, txid, 0, recipient_id, amount) != OK ||
            add_output(ledger, txid, 1, "SYSTEM", TX_FEE) != OK ||
            (change > 0.000001 &&
             add_output(ledger, txid, 2, sender_id, change) != OK))
            return ERR_CAPACITY;
        append_history(ledger, sender_id, recipient_id, amount, TX_FEE, 0);
    }
    printf("[transaction] %s -> %s: %d coins, fee %d, tx %.16s...\n",
           sender_id, recipient_id, amount, TX_FEE, txid);
    return OK;
}

void tx_print_balances(const TokenLedger *ledger)
{
    int i;
    printf("\n================ TOKEN BALANCES (%s) ================\n",
           ledger->model == TX_MODEL_UTXO ? "UTXO" : "ACCOUNT");
    printf("%-12s %-28s %10s%s\n", "MEMBER ID", "NAME", "BALANCE",
           ledger->model == TX_MODEL_ACCOUNT ? "  NONCE" : "");
    for (i = 0; i < ledger->account_count; i++) {
        const TxAccount *account = &ledger->accounts[i];
        double balance = ledger->model == TX_MODEL_ACCOUNT
                          ? account->balance
                          : utxo_balance(ledger, account->member_id);
        printf("%-12s %-28.28s %10.2f", account->member_id,
               account->member_name, balance);
        if (ledger->model == TX_MODEL_ACCOUNT)
            printf("  %llu", (unsigned long long)account->nonce);
        putchar('\n');
    }
    printf("======================================================\n");
}

void tx_print_utxos(const TokenLedger *ledger)
{
    int i, count = 0;
    if (ledger->model != TX_MODEL_UTXO) {
        printf("UTXO set is available only when UTXO model is selected.\n");
        return;
    }
    printf("\n================ UNSPENT TRANSACTION OUTPUTS ================\n");
    printf("%-18s %-6s %-12s %8s\n", "TX ID", "INDEX", "OWNER", "COINS");
    for (i = 0; i < ledger->output_count; i++) {
        const UTXO *output = &ledger->outputs[i];
        if (output->spent) continue;
        printf("%.16s... %-6u %-12s %8.2f\n", output->transaction_id,
               output->output_index, output->owner, output->amount);
        count++;
    }
    printf("%d unspent output(s).\n", count);
    printf("=============================================================\n");
}

void tx_print_history(const TokenLedger *ledger, const char *member_id)
{
    const TxAccount *account = find_account_const(ledger, member_id);
    const TxHistoryEntry *entry;
    if (account == NULL) {
        printf("ERROR: member '%s' is not registered.\n", member_id);
        return;
    }
    printf("\nTransaction history for %s (%s)\n", account->member_name,
           account->member_id);
    printf("%-12s %-12s %8s %6s %8s\n", "SENDER", "RECIPIENT",
           "AMOUNT", "FEE", "NONCE");
    for (entry = account->history_head; entry != NULL; entry = entry->next)
        printf("%-12s %-12s %8.2f %6.2f %8llu\n", entry->sender,
               entry->recipient, entry->amount, entry->fee,
               (unsigned long long)entry->nonce);
    if (account->history_head == NULL) printf("No transactions recorded.\n");
}