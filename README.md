
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
## 2. Dependencies

- **GCC** (or any C11 compiler) and **GNU Make**
- **OpenSSL development headers** (`libcrypto`) — for SHA-256 and ECDSA

### Install

```bash
# Debian / Ubuntu / WSL
sudo apt-get update
sudo apt-get install -y build-essential libssl-dev

# Fedora / RHEL
sudo dnf install -y gcc make openssl-devel

# macOS
brew install openssl@3
```

### Build

```bash
make
./library_chain
```

## 3. Compilation instructions

```bash
git clone <https://github.com/Noella-Ntare/blockchain_FA1>
cd library-blockchain
make
```

This produces the executable `./library_chain`. The build is warning-clean
under `-Wall -Wextra -Wpedantic`.

Manual compilation without Make:

```bash
gcc -std=c11 -Wall -Wextra -O2 -Iinclude src/*.c -o library_chain -lcrypto
```


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


### A small walkthrough

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
---
