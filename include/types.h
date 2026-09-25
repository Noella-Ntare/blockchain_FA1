
#ifndef TYPES_H
#define TYPES_H

#include <time.h>
#include <stddef.h>

/* Static limits for the local registry and ledger. */
#define MAX_BOOKS          512
#define MAX_MEMBERS        512
#define MAX_BLOCKS        4096

/* Hash and signature sizing. */
#define HASH_HEX_LEN        65   /* 64 hex chars + NUL */
#define SIG_MAX_LEN         72   /* maximum DER-encoded P-256 signature */
#define SIG_HEX_LEN        (SIG_MAX_LEN * 2 + 1)

/* Loan age before a record is considered overdue. */
#ifndef LOAN_PERIOD_DAYS
#define LOAN_PERIOD_DAYS    14
#endif

/* File names */
#define BOOKS_FILE     "books.txt"
#define MEMBERS_FILE   "members.txt"
#define CHAIN_FILE     "chain.dat"
#define AUTH_FILE      "auth.dat"
#define PRIV_KEY_FILE  "keys/librarian_private.pem"
#define PUB_KEY_FILE   "keys/librarian_public.pem"
#define KEY_DIR        "keys"

/* Action labels used in blocks. */
#define ACTION_BORROWED "BORROWED"
#define ACTION_RETURNED "RETURNED"
#define ACTION_OVERDUE  "OVERDUE"
#define ACTION_GENESIS  "GENESIS"

/* One book recorded in the book registry. */
typedef struct {
    char book_id[20];
    char title[80];
    char author[50];
} Book;

/* One member recorded in the member registry. */
typedef struct {
    char member_id[20];
    char full_name[50];
    char course_code[10];
} Member;

/* A single signed ledger entry. */
typedef struct {
    int           index;
    time_t        timestamp;
    char          book_id[20];
    char          book_title[80];
    char          member_id[20];
    char          member_name[50];
    char          action[10];
    char          previous_hash[HASH_HEX_LEN];
    unsigned char signature[SIG_MAX_LEN];
    size_t        sig_len;
    char          hash[HASH_HEX_LEN];
} Block;

/* Ordered list of blocks forming the append-only ledger. */
typedef struct {
    Block blocks[MAX_BLOCKS];
    int   count;
} Blockchain;

/* In-memory registry tables loaded from the CSV files. */
typedef struct {
    Book   books[MAX_BOOKS];
    int    book_count;
    Member members[MAX_MEMBERS];
    int    member_count;
} Registry;

/* Common return codes used by the project. */
typedef enum {
    OK                 =  0,
    ERR_FILE_MISSING   = -1,
    ERR_FILE_EMPTY     = -2,
    ERR_BAD_FORMAT     = -3,
    ERR_NOT_FOUND      = -4,
    ERR_CAPACITY       = -5,
    ERR_CRYPTO         = -6,
    ERR_DUPLICATE      = -7,
    ERR_CONFLICT       = -8
} Status;

#endif /* TYPES_H */
