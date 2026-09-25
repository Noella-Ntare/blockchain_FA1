# Blockchain-Based Library Book Lending Tracker

A command-line library lending ledger written in C, in which every borrow,
return and overdue event is stored as a block in an append-only chain. Each
block is signed with an **ECDSA (NIST P-256)** digital signature and linked to
its predecessor with a **SHA-256** hash, so any later edit to a past record is
detected immediately.

---

## 1. Features

| # | Requirement | Where it lives |
|---|---|---|
| 1 | Blockchain data structure holding lending records | `include/types.h`, `src/blockchain.c` |
| 2 | Book and member registries loaded from file and validated before any action | `src/registry.c` |
| 3 | SHA-256 hashing linking blocks | `sha256_hex()`, `bc_compute_hash()` |
| 4 | ECDSA digital signatures authenticating lending actions | `crypto_sign()`, `crypto_verify()` |
| 5 | Chain validation logic detecting tampering | `bc_validate()` |
| 6 | CLI to borrow, return and view lending records | `src/main.c` |
| + | Password authentication and role-based access control | `auth_login()` |
| + | File persistence of the ledger | `src/storage.c` |
| + | OVERDUE detection (14-day loan period) | `bc_flag_overdue()` |

---

## 2. Required libraries and dependencies

| Dependency | Version | Purpose |
|---|---|---|
| GCC (or Clang) | C11 capable | compiler |
| GNU Make | any | build driver |
| OpenSSL `libcrypto` | 1.1.1 or 3.x | SHA-256, ECDSA P-256, secure random salts |

Everything else is ISO C11 plus POSIX (`termios.h` for non-echoing password
input, `sys/stat.h` for key-file permissions).

### Installing OpenSSL development headers

```bash
# Debian / Ubuntu
sudo apt-get update && sudo apt-get install -y build-essential libssl-dev

# Fedora / RHEL
sudo dnf install -y gcc make openssl-devel

# macOS (Homebrew)
brew install openssl@3
# then build with:
#   make CFLAGS="-std=c11 -Wall -Wextra -O2 -Iinclude -I$(brew --prefix openssl@3)/include" \
#        LDFLAGS="-L$(brew --prefix openssl@3)/lib"
```

---

## 3. Compilation instructions

```bash
git clone <your-repository-url>
cd library-blockchain
make
```

This produces the executable `./library_chain`. The build is warning-clean
under `-Wall -Wextra -Wpedantic`.

Manual compilation without Make:

```bash
gcc -std=c11 -Wall -Wextra -O2 -Iinclude src/*.c -o library_chain -lcrypto
```

Make targets:

| Target | Effect |
|---|---|
| `make` | build `./library_chain` |
| `make run` | build then run |
| `make clean` | delete `build/` and the executable |
| `make reset` | `clean` plus delete `chain.dat`, `keys/` and `auth.dat` (fresh demo) |
| `make demo-overdue` | build `./library_chain_overdue` with a 0-day loan period so the OVERDUE path can be shown without waiting two weeks |

---

## 4. How to run

```bash
./library_chain
```

On the **first run** the program:

1. loads `books.txt` and `members.txt` (aborts if either is missing or empty);
2. generates an ECDSA P-256 key pair into `keys/` (private key `chmod 0600`);
3. creates `auth.dat` with two default accounts;
4. creates the genesis block and writes `chain.dat`.

On every **later run** it reloads `chain.dat` and validates the whole chain
before the menu appears.

### Default accounts

| Username | Password | Role | Rights |
|---|---|---|---|
| `librarian` | `library123` | LIBRARIAN | borrow, return, overdue sweep, tamper demo, plus everything below |
| `viewer` | `view123` | VIEWER | view records, validate chain, list registries |

Passwords are never stored: `auth.dat` holds `SHA-256(salt + password)` with a
16-byte random salt per account. Change them by deleting `auth.dat` and editing
`auth_bootstrap()`, or by generating a new hash yourself.

### Menu

```
  1. Borrow a book            (librarian)
  2. Return a book            (librarian)
  3. View lending records
  4. Validate the chain
  5. Books currently on loan
  6. List book registry
  7. List member registry
  8. Flag overdue loans       (librarian)
  9. Tamper demo              (librarian)
 10. Re-load ledger from disk
  0. Exit
```

### A two-minute walkthrough

```
1  ->  BK001 / ALU001      record a loan          (block #1 appended)
1  ->  BK999 / ALU001      ERROR: Book or Member not found
1  ->  BK002 / ALU999      ERROR: Book or Member not found
1  ->  BK001 / ALU003      ERROR: already on loan to John Doe
3                          view the whole ledger with signature status
4                          validate: CHAIN VALID
2  ->  BK001 / ALU001      record the return      (block #2 appended)
9  ->  block 1, field 1    tamper demo: CHAIN INVALID, block 1 named
10                         reload the authentic ledger from disk
```

---

## 5. Input file formats

`books.txt` — `book_id,title,author`

```
BK001,Things Fall Apart,Chinua Achebe
BK002,Americanah,Chimamanda Ngozi Adichie
BK003,The River Between,Ngũgĩ wa Thiong'o
```

`members.txt` — `member_id,full_name,course_code`

```
ALU001,John Doe,BLK101
ALU002,Jane Smith,BLK101
ALU003,Amara Diallo,BLK101
```

Blank lines and lines starting with `#` are ignored. Malformed lines, empty
fields and duplicate IDs are reported and skipped rather than silently
accepted. If a file is missing or contains no valid record, the program prints
a specific error and exits without touching the ledger.

---

## 6. Files the program creates

| File | Contents | Permissions |
|---|---|---|
| `chain.dat` | the ledger, one pipe-delimited block per line | 0644 |
| `keys/librarian_private.pem` | ECDSA P-256 private key (signing) | 0600 |
| `keys/librarian_public.pem` | ECDSA P-256 public key (verification) | 0644 |
| `auth.dat` | `user:salt:sha256(salt+password):role` | 0600 |

`chain.dat` record layout:

```
index|timestamp|book_id|book_title|member_id|member_name|action|previous_hash|signature_hex|hash
```

---

## 7. How tamper detection works

```
payload   = index | timestamp | book_id | book_title | member_id |
            member_name | action | previous_hash
signature = ECDSA-SHA256(payload)            signed with the private key
hash      = SHA-256(payload || signature)    stored in the block
block[i].previous_hash == block[i-1].hash    the chain link
```

`bc_validate()` checks four things for every block: the index sequence, the
recomputed hash against the stored hash, the link to the previous block, and
the ECDSA signature against the public key.

Two ways to see it work:

**In-program (menu option 9).** Change `member_name` on block 1; validation
reports the stored hash, the recomputed hash and the failed signature. Option
10 reloads the authentic ledger — nothing was written to disk.

**Outside the program.** Edit `chain.dat` in any text editor:

```bash
sed -i 's/John Doe/Mallory Hacker/' chain.dat
./library_chain          # startup validation fails and names the block
```

An attacker who also recomputes that block's hash does not escape detection:
the following block still stores the *old* hash in its `previous_hash`, so the
link check fails instead. Re-signing is impossible without the private key.

---

## 8. Project layout

```
library-blockchain/
├── Makefile
├── README.md
├── books.txt                  # book registry
├── members.txt                # member registry
├── include/
│   ├── types.h                # Book, Member, Block, Blockchain, Registry
│   ├── registry.h
│   ├── crypto_utils.h
│   ├── blockchain.h
│   └── storage.h
├── src/
│   ├── main.c                 # CLI, startup sequence, access control
│   ├── registry.c             # CSV loading, validation, look-ups
│   ├── crypto_utils.c         # SHA-256, ECDSA, salted password auth
│   ├── blockchain.c           # block creation, hashing, validation
│   └── storage.c              # chain.dat load/save, tamper demo helper
└── docs/
    ├── system_design.svg/.png # system design diagram
    └── screenshots/           # execution screenshots used in the report
```

---

## 9. Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `fatal error: openssl/evp.h: No such file` | OpenSSL headers missing — install `libssl-dev` / `openssl-devel` |
| `undefined reference to 'EVP_DigestSignInit'` | `-lcrypto` missing from the link line |
| `ERROR: Required file 'books.txt' is missing` | run the program from the project root, where the registries live |
| `FATAL: 'chain.dat' is corrupt` | a line no longer has 10 fields — restore the file or move it aside to start a fresh ledger |
| Startup says the ledger FAILED validation | the ledger really was modified; option 3 and option 4 show which block |
| Signature shows `BAD` for every block | `keys/` was deleted or replaced after the blocks were signed; the old blocks can no longer be verified with the new key |

---

## 10. Author

`<Your Name>` — `<Student ID>`
`<Course code / Institution>` — Assignment 1
