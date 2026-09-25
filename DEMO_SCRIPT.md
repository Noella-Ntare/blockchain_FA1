# Demo Video Script (3–5 minutes)

Everything the rubric asks to see, in the order it should be shown. Run
`make reset && make` first so the genesis block is created on camera.

Record at 1080p or higher, with the terminal font large enough to read the
hashes. Keep the whole terminal visible — the hash values are the evidence.

---

## 0:00 – 0:25 · Introduction

> "This is a blockchain-based library book lending tracker written in C. Every
> borrow and return is stored as a block, signed with an ECDSA key and linked
> to the previous block with a SHA-256 hash, so any change to a past record is
> detected. I'm <your name>, student ID <id>."

Show the project folder briefly: `ls` then `cat books.txt` and `cat members.txt`
so the registry formats are visible.

---

## 0:25 – 1:00 · Startup, registry loading, key generation, genesis block

```bash
make reset      # only for the recording, so the first run is captured
make
./library_chain
```

Point out, as each line appears:

- `[registry] Loaded 10 book(s)… and 8 member(s)…` — **registry loading**
- `[crypto] … generating a new ECDSA P-256 key pair` — key pair created, private
  key `0600`
- the login prompt — **authentication**; type `librarian` / `library123`
  (the password does not echo)
- `[chain] Genesis block created` — index 0, `previous_hash` is 64 zeros

---

## 1:00 – 1:40 · Valid lending action

Menu **1**, then `BK001`, `ALU001`.

Say what the block shows: index 1, the title and member name copied from the
registry, the action `BORROWED`, the `previous_hash` matching the genesis hash,
a 71-byte DER signature marked `VALID`, and the block's own hash.

Record a second loan so the chain is longer: menu **1**, `BK007`, `ALU005`.

---

## 1:40 – 2:15 · Invalid IDs and rejected transactions

Three rejections in a row — this is the "invalid student ID handling" the
rubric asks for:

| Menu | Input | Expected |
|---|---|---|
| 1 | `BK999` / `ALU001` | `ERROR: Book or Member not found` → book_id not in books.txt |
| 1 | `BK002` / `ALU999` | `ERROR: Book or Member not found` → member_id not in members.txt |
| 1 | `BK001` / `ALU003` | `ERROR: … already on loan to John Doe (ALU001)` |

> "In all three cases no block was created — the chain is untouched."

---

## 2:15 – 2:50 · Viewing records and returning a book

Menu **3** — every block with timestamp, book title, member name, action and
signature status `OK`.

Menu **5** — books currently on loan.

Menu **2**, `BK001`, `ALU001` — the return is appended as a new `RETURNED`
block.

> "Note that returning does not edit the earlier block. The chain is
> append-only; the loan is closed by adding a record, never by changing one."

---

## 2:50 – 3:20 · Chain validation

Menu **4**.

Walk through what the four checks mean while the output is on screen: index
sequence, recomputed hash vs stored hash, `previous_hash` linkage, and ECDSA
signature verification. End on `RESULT: CHAIN VALID`.

---

## 3:20 – 4:20 · Tamper detection

**In-program.** Menu **9** → block `1` → field `1` (member_name) → type
`Mallory Hacker`.

Read out the failure: the stored hash and the recomputed hash differ, the
signature no longer verifies, and validation names block 1.

> "An attacker who also recomputes this block's hash doesn't escape either —
> block 2 still stores the old hash in its previous_hash, so the link check
> fails instead. And re-signing is impossible without the private key."

Menu **10** to reload the authentic ledger, then menu **4** — valid again.

**Outside the program** (stronger, if time allows). Exit with **0**, then:

```bash
sed -i 's/John Doe/Mallory Hacker/' chain.dat
./library_chain
```

Startup validation fails before the menu appears. Restore with
`git checkout chain.dat` or re-run `make reset`.

---

## 4:20 – 4:45 · Access control (optional, if within time)

Exit, re-run, log in as `viewer` / `view123`, press **1**:

`ACCESS DENIED: role 'VIEWER' may only read the ledger.`

---

## 4:45 – 5:00 · Close

> "So every lending event is cryptographically signed, hash-linked to its
> predecessor, persisted to disk and re-validated on every startup. Thanks for
> watching."

---

## Checklist before uploading

- [ ] Registry loading is visible
- [ ] A valid transaction is recorded
- [ ] Invalid book ID **and** invalid member ID are both rejected on camera
- [ ] Records are viewed
- [ ] Chain validation passes
- [ ] Tamper detection fails the chain and names the block
- [ ] Your name and student ID are stated or on screen
- [ ] Length is between 3 and 5 minutes
- [ ] Audio is clear; hashes are legible
