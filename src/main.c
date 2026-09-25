/* CLI front end for the library blockchain demo. */
#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "types.h"
#include "registry.h"
#include "crypto_utils.h"
#include "blockchain.h"
#include "storage.h"

static Registry   g_registry;
static Blockchain g_chain;
static EVP_PKEY  *g_key  = NULL;
static char       g_role[16] = "VIEWER";
static char       g_user[64] = "guest";

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
        printf("[storage] Ledger saved to %s (%d block(s)).\n",
               CHAIN_FILE, g_chain.count);
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
    Blockchain fresh;
    if (storage_load_chain(&fresh) == OK) {
        g_chain = fresh;
        printf("[storage] Ledger reloaded. Re-validating...\n");
        bc_validate(&g_chain, g_key, 1);
    } else {
        printf("ERROR: could not reload the ledger from %s.\n", CHAIN_FILE);
    }
}

int main(void)
{
    char choice[16];
    int  rc, running = 1;

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
        else if (strcmp(choice, "0")  == 0) running = 0;
        else if (choice[0] == '\0')         continue;
        else printf("ERROR: '%s' is not a valid menu option.\n", choice);
    }

    printf("\nGoodbye. The ledger holds %d block(s).\n", g_chain.count);
    EVP_PKEY_free(g_key);
    return EXIT_SUCCESS;
}
