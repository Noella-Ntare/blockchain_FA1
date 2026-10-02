/* CLI front end for the library blockchain demo. */
#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "types.h"
#include "registry.h"
#include "crypto_utils.h"
#include "blockchain.h"
#include "storage.h"
#include "tx_ledger.h"

static Registry   g_registry;
static Blockchain g_chain;
static TokenLedger g_tokens;
static EVP_PKEY  *g_key  = NULL;
static char       g_role[16] = "VIEWER";
static char       g_user[64] = "guest";
static TxModel    g_model = TX_MODEL_UTXO;
static int        g_model_selected;
static int        g_difficulty = 2;

/* --------------------------------------------------------------- */
static void read_line(const char *prompt, char *buf, size_t sz)
{
    printf("%s", prompt);
    fflush(stdout);
    if (fgets(buf, (int)sz, stdin) == NULL) { buf[0] = '\0'; return; }
    buf[strcspn(buf, "\r\n")] = '\0';
    {   /* trim */
        char *p = str_trim(buf);
        if (p != buf) memmove(buf, p, strlen(p) + 1);
    }
}

static int is_librarian(void)
{
    if (strcmp(g_role, "LIBRARIAN") == 0) return 1;
    printf("\nACCESS DENIED: role '%s' may only read the ledger. "
           "Log in as a librarian to record transactions.\n", g_role);
    return 0;
}

static void persist(void)
{
    if (storage_save_chain(&g_chain) == OK)
         printf("[storage] Ledger saved to %s (%d confirmed, %d pending).\n",
             CHAIN_FILE, g_chain.count, g_chain.pending_count);
    else
        fprintf(stderr, "ERROR: the ledger could NOT be saved.\n");
}

/* --------------------------------------------------------------- */
static void banner(void)
{
    printf("\n");
    printf("============================================================\n");
    printf("     BLOCKCHAIN-BASED LIBRARY BOOK LENDING TRACKER\n");
    printf("     SHA-256 hash chain  +  ECDSA P-256 digital signatures\n");
    printf("============================================================\n");
}

static void menu(void)
{
    printf("\n------------------ MENU (%s: %s) ------------------\n",
           g_role, g_user);
    printf("  1. Borrow a book            (librarian)\n");
    printf("  2. Return a book            (librarian)\n");
    printf("  3. View lending records\n");
    printf("  4. Validate the chain\n");
    printf("  5. Books currently on loan\n");
    printf("  6. List book registry\n");
    printf("  7. List member registry\n");
    printf("  8. Flag overdue loans       (librarian)\n");
    printf("  9. Tamper demo              (librarian)\n");
    printf(" 10. Re-load ledger from disk\n");
    printf(" 11. Show pending pool\n");
    printf(" 12. Mine pending blocks (difficulty %d)\n", g_difficulty);
    printf(" 13. Show token balances\n");
    printf(" 14. Show full UTXO set\n");
    printf(" 15. Transfer tokens\n");
    printf(" 16. Member transaction history\n");
    printf("  0. Exit\n");
    printf("------------------------------------------------------------\n");
    printf("Choice: ");
    fflush(stdout);
}

/* --------------------------------------------------------------- */
static void do_borrow(void)
{
    char book_id[20], member_id[20];

    if (!is_librarian()) return;

    read_line("Book ID   (e.g. BK001) : ", book_id,   sizeof(book_id));
    read_line("Member ID (e.g. ALU001): ", member_id, sizeof(member_id));

    if (book_id[0] == '\0' || member_id[0] == '\0') {
        printf("ERROR: both a book ID and a member ID are required.\n");
        return;
    }
    if (bc_borrow(&g_chain, &g_registry, g_key, book_id, member_id) == OK)
        persist();
}

static void do_return(void)
{
    char book_id[20], member_id[20];

    if (!is_librarian()) return;

    read_line("Book ID   : ", book_id,   sizeof(book_id));
    read_line("Member ID : ", member_id, sizeof(member_id));

    if (book_id[0] == '\0' || member_id[0] == '\0') {
        printf("ERROR: both a book ID and a member ID are required.\n");
        return;
    }
    if (bc_return(&g_chain, &g_registry, g_key, book_id, member_id) == OK)
        persist();
}

static void do_overdue(void)
{
    int flagged = 0;
    if (!is_librarian()) return;

    printf("\n[overdue] Scanning open loans older than %d days...\n",
           LOAN_PERIOD_DAYS);
    if (bc_flag_overdue(&g_chain, g_key, &flagged) == OK && flagged > 0)
        persist();
}

static void do_tamper(void)
{
    char sidx[16], field[8], value[128];
    int  idx, choice;

    if (!is_librarian()) return;

    printf("\n*** TAMPER DETECTION DEMONSTRATION ***\n");
    printf("This intentionally corrupts a sealed block so you can watch\n");
    printf("chain validation catch it. Use option 10 afterwards to reload\n");
    printf("the untouched ledger from disk.\n");

    read_line("\nBlock index to modify: ", sidx, sizeof(sidx));
    idx = atoi(sidx);

    printf("  1. member_name\n  2. book_title\n  3. action\n  4. timestamp\n");
    read_line("Field to change: ", field, sizeof(field));
    choice = atoi(field);

    read_line("New value: ", value, sizeof(value));

    if (storage_tamper_block(&g_chain, idx, choice, value) != OK) return;

    printf("\nRe-running validation on the modified chain:\n");
    bc_validate(&g_chain, g_key, 1);

    printf("\nNOTE: the tampered chain was NOT written to disk. Choose 10 to\n"
           "      restore the authentic ledger.\n");
}

static void do_reload(void)
{
    static Blockchain fresh;
    if (storage_load_chain(&fresh) == OK) {
        g_chain = fresh;
        printf("[storage] Ledger reloaded. Re-validating...\n");
        bc_validate(&g_chain, g_key, 1);
        tx_ledger_free(&g_tokens);
        if (tx_ledger_init(&g_tokens, &g_registry, &g_chain, g_model) != OK)
            printf("ERROR: token balances could not be reconstructed.\n");
    } else {
        printf("ERROR: could not reload the ledger from %s.\n", CHAIN_FILE);
    }
}

static int read_number(const char *prompt, int min_value, int max_value)
{
    char input[32];
    int value;
    read_line(prompt, input, sizeof(input));
    value = atoi(input);
    if (value < min_value || value > max_value) return -1;
    return value;
}

static int choose_model(void)
{
    char choice[16];
    if (g_model_selected) return 1;
    printf("\nSelect token transaction model for this session:\n"
           "  1. UTXO\n  2. Account-based\n");
    read_line("Model: ", choice, sizeof(choice));
    if (strcmp(choice, "1") == 0) g_model = TX_MODEL_UTXO;
    else if (strcmp(choice, "2") == 0) g_model = TX_MODEL_ACCOUNT;
    else {
        printf("ERROR: choose 1 (UTXO) or 2 (account).\n");
        return 0;
    }
    g_model_selected = 1;
    printf("[tokens] %s model selected; each return reward pays a %d-coin fee.\n",
           g_model == TX_MODEL_UTXO ? "UTXO" : "Account", TX_FEE);
    return 1;
}

static void do_transfer(void)
{
    char sender[20], recipient[20], value[32], nonce_text[32];
    int amount;
    uint64_t nonce = 0;
    if (!is_librarian()) return;
    read_line("Sender member ID   : ", sender, sizeof(sender));
    read_line("Recipient member ID: ", recipient, sizeof(recipient));
    read_line("Amount (coins)     : ", value, sizeof(value));
    amount = atoi(value);
    if (g_model == TX_MODEL_ACCOUNT) {
        read_line("Outgoing nonce     : ", nonce_text, sizeof(nonce_text));
        nonce = (uint64_t)strtoull(nonce_text, NULL, 10);
    }
    tx_transfer(&g_tokens, sender, recipient, amount, nonce);
}

static void do_history(void)
{
    char member_id[20];
    read_line("Member ID: ", member_id, sizeof(member_id));
    tx_print_history(&g_tokens, member_id);
}

static int read_mining_member(const char *prompt, char member_id[20])
{
    read_line(prompt, member_id, 20);
    if (registry_find_member(&g_registry, member_id) == NULL) {
        printf("ERROR: mining payout recipient must be a registered member ID.\n");
        return 0;
    }
    return 1;
}

static int credit_mining_reward(const char *method, const char *member_id,
                                int sequence, double amount)
{
    static unsigned long reward_sequence;
    char material[192], transaction_id[HASH_HEX_LEN];

    if (amount <= 0.0) return OK;
    snprintf(material, sizeof(material), "%s|%s|%d|%.8f|%lu|%lld",
             method, member_id, sequence, amount, ++reward_sequence,
             (long long)time(NULL));
    if (sha256_hex(material, strlen(material), transaction_id) != OK)
        return ERR_CRYPTO;
    if (tx_mining_credit(&g_tokens, member_id, transaction_id,
                         (unsigned int)sequence, amount) != OK) {
        printf("ERROR: could not credit %.2f mining coin(s) to %s.\n",
               amount, member_id);
        return ERR_CAPACITY;
    }
    return OK;
}

static void do_mine(void)
{
    int method, confirmed = 0, old_count, i, miners = 0;
    int rounds = 0, rates[8], rates_total = 0;
    uint64_t attempts = 0;
    char solo_member[20], cloud_member[20], pool_members[8][20];

    if (!is_librarian()) return;
    bc_print_pending(&g_chain);
    if (g_chain.pending_count == 0) return;
    method = read_number("Mining method (1 solo, 2 pool, 3 cloud): ", 1, 3);
    if (method < 0) {
        printf("ERROR: choose a mining method from 1 to 3.\n");
        return;
    }
    if (method == 2) {
        miners = read_number("Number of pool miners (2-8): ", 2, 8);
        if (miners < 0) {
            printf("ERROR: pool requires 2 to 8 miners.\n");
            return;
        }
        for (i = 0; i < miners; i++) {
            char prompt[64];
            snprintf(prompt, sizeof(prompt), "Miner %d payout member ID: ", i + 1);
            if (!read_mining_member(prompt, pool_members[i])) return;
        }
        srand((unsigned int)time(NULL));
        for (i = 0; i < miners; i++) {
            rates[i] = 100 + rand() % 901;
            rates_total += rates[i];
        }
    } else if (method == 1) {
        if (!read_mining_member("Solo miner payout member ID: ", solo_member))
            return;
    }
    if (method == 3) {
        rounds = read_number("Cloud rental duration (1-5 rounds): ", 1, 5);
        if (rounds < 0) {
            printf("ERROR: rental duration must be 1 to 5 rounds.\n");
            return;
        }
        if (!read_mining_member("Cloud mining payout member ID: ", cloud_member))
            return;
    }

    old_count = g_chain.count;
    if (bc_mine_pending(&g_chain, g_key, g_difficulty,
                        &attempts, &confirmed) != OK || confirmed == 0)
        return;

    for (i = old_count; i < g_chain.count; i++)
        if (tx_confirm_block(&g_tokens, &g_chain.blocks[i]) != OK)
            printf("ERROR: token transaction for block #%d could not be applied.\n",
                   i);
        else {
            tx_print_balances(&g_tokens);
            if (g_model == TX_MODEL_UTXO) tx_print_utxos(&g_tokens);
        }

    if (method == 1) {
        double reward = confirmed * 2.0;
        credit_mining_reward("SOLO", solo_member, old_count, reward);
        printf("Solo miner %s receives %.2f mining coin(s).\n",
               solo_member, reward);
    } else if (method == 2) {
        uint64_t allocated = 0;
        double gross = confirmed * 2.0;
        double pool_fee = gross * 0.02;
        printf("\nPOOL MINING (gross %.2f, 2%% pool fee %.2f)\n",
               gross, pool_fee);
        printf("%-10s %-12s %-12s %-12s %-14s %-12s\n",
               "MINER ID", "MEMBER", "ATTEMPTS", "SHARE %",
               "GROSS SHARE", "NET REWARD");
        for (i = 0; i < miners; i++) {
            uint64_t share_attempts = i == miners - 1
                ? attempts - allocated
                : attempts * (uint64_t)rates[i] / (uint64_t)rates_total;
            double share = attempts == 0 ? 0.0
                : (double)share_attempts / (double)attempts;
            double gross_share = gross * share;
            double net_reward = (gross - pool_fee) * share;
            allocated += share_attempts;
            credit_mining_reward("POOL", pool_members[i], old_count + i,
                                 net_reward);
            printf("miner-%-4d %-12s %-12llu %8.2f%% %-14.2f %-12.2f\n",
                   i + 1, pool_members[i],
                   (unsigned long long)share_attempts, share * 100.0,
                   gross_share, net_reward);
        }
        printf("Pool rewards are credited by actual allocated attempt share.\n");
    } else {
        double gross_total = confirmed * 2.0;
        double fees_total = rounds * 3.0;
        double net_total = gross_total - fees_total;
        double gross_so_far = 0.0;
        double fees_so_far = 0.0;
        double paid_so_far = 0.0;
        printf("\nCLOUD MINING (%d rounds; rental 2.00 + maintenance 1.00 / round)\n",
               rounds);
        printf("%-7s %-12s %-10s %-10s %-10s %-10s\n",
               "ROUND", "GROSS", "RENTAL", "MAINT", "NET CUM.", "PAID");
        for (i = 1; i <= rounds; i++) {
            double round_gross = i == rounds
                ? gross_total - gross_so_far
                : gross_total / rounds;
            double round_fees = 3.0;
            double cumulative_profit, credit_now;
            gross_so_far += round_gross;
            fees_so_far += round_fees;
            cumulative_profit = gross_so_far - fees_so_far;
            credit_now = cumulative_profit > paid_so_far
                       ? cumulative_profit - paid_so_far : 0.0;
            if (credit_now > 0.0) {
                credit_mining_reward("CLOUD", cloud_member, old_count + i,
                                     credit_now);
                paid_so_far += credit_now;
            }
            printf("%-7d %-12.2f %-10.2f %-10.2f %-10.2f %-10.2f\n",
                   i, round_gross, 2.0, 1.0, cumulative_profit, credit_now);
            if (cumulative_profit < 0.0)
                printf("WARNING: cloud rental is unprofitable by round %d.\n", i);
        }
        printf("Gross earnings: %.2f | Total fees: %.2f | Net profit: %.2f\n",
               gross_so_far, fees_so_far, net_total);
        if (paid_so_far < net_total) {
            double final_credit = net_total - paid_so_far;
            credit_mining_reward("CLOUD", cloud_member, old_count + rounds,
                                 final_credit);
            paid_so_far += final_credit;
        }
        if (net_total <= 0.0)
            printf("No mining payout credited; rental fees exceed rewards.\n");
        else
            printf("Cloud net earnings credited to %s: %.2f coins.\n",
                   cloud_member, paid_so_far);
    }

    tx_print_balances(&g_tokens);
    if (g_model == TX_MODEL_UTXO) tx_print_utxos(&g_tokens);
    persist();
}

int main(int argc, char **argv)
{
    char choice[16];
    int  rc, running = 1, argi;

    for (argi = 1; argi < argc; argi++) {
        if (strcmp(argv[argi], "--difficulty") == 0 && argi + 1 < argc) {
            g_difficulty = atoi(argv[++argi]);
            if (g_difficulty < 1 || g_difficulty > 4) {
                fprintf(stderr, "Difficulty must be in the range 1 to 4.\n");
                return EXIT_FAILURE;
            }
        } else if (strcmp(argv[argi], "--model") == 0 && argi + 1 < argc) {
            argi++;
            if (strcmp(argv[argi], "utxo") == 0) g_model = TX_MODEL_UTXO;
            else if (strcmp(argv[argi], "account") == 0)
                g_model = TX_MODEL_ACCOUNT;
            else {
                fprintf(stderr, "Model must be 'utxo' or 'account'.\n");
                return EXIT_FAILURE;
            }
            g_model_selected = 1;
        } else {
            fprintf(stderr, "Usage: %s [--model utxo|account] [--difficulty 1-4]\n",
                    argv[0]);
            return EXIT_FAILURE;
        }
    }

    banner();

    /* ---- 1. registries ------------------------------------------ */
    if (registry_load(&g_registry) != OK) {
        fprintf(stderr, "\nFATAL: registries could not be loaded. "
                        "Startup aborted.\n");
        return EXIT_FAILURE;
    }

    /* ---- 2. cryptographic keys ---------------------------------- */
    g_key = crypto_load_or_generate_keys();
    if (g_key == NULL) {
        fprintf(stderr, "\nFATAL: no usable signing key. Startup aborted.\n");
        return EXIT_FAILURE;
    }

    /* ---- 3. authentication -------------------------------------- */
    if (auth_bootstrap() != OK) {
        fprintf(stderr, "\nFATAL: authentication store unavailable.\n");
        EVP_PKEY_free(g_key);
        return EXIT_FAILURE;
    }
    printf("\nAuthentication required.\n");
    if (auth_login(g_role, sizeof(g_role), g_user, sizeof(g_user)) != OK) {
        fprintf(stderr, "\nFATAL: too many failed login attempts. "
                        "Exiting.\n");
        EVP_PKEY_free(g_key);
        return EXIT_FAILURE;
    }

    /* ---- 4. ledger ---------------------------------------------- */
    rc = storage_load_chain(&g_chain);
    if (rc == ERR_FILE_MISSING) {
        printf("[storage] No ledger found - initialising a new chain.\n");
        if (bc_init(&g_chain, g_key) != OK) {
            fprintf(stderr, "FATAL: genesis block creation failed.\n");
            EVP_PKEY_free(g_key);
            return EXIT_FAILURE;
        }
        persist();
    } else if (rc != OK) {
        fprintf(stderr, "FATAL: '%s' is corrupt. Move it aside and restart "
                        "to begin a fresh ledger.\n", CHAIN_FILE);
        EVP_PKEY_free(g_key);
        return EXIT_FAILURE;
    } else {
        /* ---- 5. integrity check on startup ---------------------- */
        if (bc_validate(&g_chain, g_key, 1) > 0)
            printf("\nWARNING: the ledger loaded from disk FAILED validation. "
                   "Investigate before recording new transactions.\n");
    }

    if (!choose_model() ||
        tx_ledger_init(&g_tokens, &g_registry, &g_chain, g_model) != OK) {
        fprintf(stderr, "FATAL: token ledger initialization failed.\n");
        EVP_PKEY_free(g_key);
        return EXIT_FAILURE;
    }
    printf("[mining] Proof-of-work difficulty: %d leading zero(s).\n",
           g_difficulty);
        printf("[tokens] %s transaction model selected.\n",
            g_model == TX_MODEL_UTXO ? "UTXO" : "Account-based");

    /* ---- main loop ---------------------------------------------- */
    while (running) {
        menu();
        if (fgets(choice, sizeof(choice), stdin) == NULL) break;
        choice[strcspn(choice, "\r\n")] = '\0';

        if      (strcmp(choice, "1")  == 0) do_borrow();
        else if (strcmp(choice, "2")  == 0) do_return();
        else if (strcmp(choice, "3")  == 0) bc_print_records(&g_chain, g_key);
        else if (strcmp(choice, "4")  == 0) bc_validate(&g_chain, g_key, 1);
        else if (strcmp(choice, "5")  == 0) bc_print_outstanding(&g_chain);
        else if (strcmp(choice, "6")  == 0) registry_print_books(&g_registry);
        else if (strcmp(choice, "7")  == 0) registry_print_members(&g_registry);
        else if (strcmp(choice, "8")  == 0) do_overdue();
        else if (strcmp(choice, "9")  == 0) do_tamper();
        else if (strcmp(choice, "10") == 0) do_reload();
        else if (strcmp(choice, "11") == 0) bc_print_pending(&g_chain);
        else if (strcmp(choice, "12") == 0) do_mine();
        else if (strcmp(choice, "13") == 0) tx_print_balances(&g_tokens);
        else if (strcmp(choice, "14") == 0) tx_print_utxos(&g_tokens);
        else if (strcmp(choice, "15") == 0) do_transfer();
        else if (strcmp(choice, "16") == 0) do_history();
        else if (strcmp(choice, "0")  == 0) running = 0;
        else if (choice[0] == '\0')         continue;
        else printf("ERROR: '%s' is not a valid menu option.\n", choice);
    }

    printf("\nGoodbye. The ledger holds %d block(s).\n", g_chain.count);
    tx_ledger_free(&g_tokens);
    EVP_PKEY_free(g_key);
    return EXIT_SUCCESS;
}
