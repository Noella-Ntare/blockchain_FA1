# Technical Report: Blockchain-Based Library Book Lending Tracker

**Course:** [Course name]  
**Student:** [Your name and ID]  
**Assessment:** Formative 2  
**Date:** [Submission date]

## 1. Introduction

This project extends the Formative 1 library lending tracker. Borrow, return, and overdue events enter a pending pool instead of being appended immediately to the confirmed blockchain. A librarian selects a mining simulation to run proof-of-work over the queued events. A confirmed return generates a reward transaction, and only then does the selected token ledger update the member's balance.

The application is written in C11 and uses OpenSSL for SHA-256 and ECDSA P-256. Book and member IDs are loaded from the supplied registry files. The block's member ID is the token account identifier.

## 2. Event and Block Flow

1. The librarian submits a borrow, return, or overdue action. Registry membership and book loan state are checked before queuing the event.
2. The event appears in the pending pool and is also persisted in `chain.dat`. It is not yet part of the confirmed chain and does not change token balances.
3. A mining method processes pending records in queue order. The miner assigns each record its final index and previous confirmed hash, signs the lending/reward payload, then increments the block nonce and recomputes SHA-256 until the configured leading-zero target is met.
4. Confirmed blocks are appended to the chain. Return reward transactions are applied to the selected token model, balances are displayed, and the ledger is saved.
5. Chain validation recalculates block hashes, verifies links and ECDSA signatures, and checks each block's recorded proof-of-work difficulty.

The new block fields are token reward, reward transaction ID, proof-of-work nonce, hash-attempt count, difficulty, and format version. The lending data, reward, transaction ID, difficulty, and previous hash are covered by the ECDSA-signed payload. The nonce is varied during mining and is included in the SHA-256 block hash. The version field preserves verification of original Formative 1 records.

## 3. Reward and Transaction Models

### Return rewards

A return within the 14-day loan period creates a nominal 10-coin reward; a later return creates 5 coins. The elapsed duration between the recorded borrow and return timestamps is used for this decision. A borrow or overdue event creates no reward transaction. Each reward transaction pays the fixed 1-coin fee, so the member receives 9 or 4 coins. The block transaction ID is a SHA-256 digest derived from member ID, book ID, timestamp, nominal reward, and event index.

### UTXO model

The UTXO ledger represents balances as unspent outputs. A confirmed return creates a member output for the net reward and a `SYSTEM` output for the fee. For a manual transfer, the application selects unspent outputs owned by the sender until they cover the requested amount plus fee. Selected outputs are marked spent; outputs are created for the recipient, fee, and any change returned to the sender. The balance is the sum of unspent outputs for a member, preventing the same output from being spent twice.

### Account-based model

The account ledger has one account per registered member, initialized with a zero balance and nonce. Confirmed returns credit the net reward. A manual outgoing transfer must provide exactly the sender's next nonce and requires a balance sufficient for amount plus fee. A successful outgoing transfer increments the sender nonce. Each member has a linked-list transaction history containing sender, recipient, amount, fee, and nonce.

The selected token model applies throughout one run. Return-derived token state is rebuilt from confirmed chain records on startup. Manual transfers and linked-list histories remain in memory for the current session.

## 4. Mining Simulations

### Solo mining

The solo miner searches for a hash beginning with the configured 1-4 zero characters. The application reports nonce and attempts for each block. The simulation assigns a 2-coin mining reward per confirmed block to the solo miner; this demonstration reward is separate from member return-token balances.

### Pool mining

Each simulated miner receives a randomized hash rate. The successful proof-of-work attempt count is allocated to miners in proportion to their rates. The displayed share is `miner attempts / total attempts`; reward is proportional to that contribution. The pool deducts 2% of gross mining rewards before distribution. The table reports miner ID, attempts, percentage, gross share, and net reward.

### Cloud mining

The user selects a rental duration of 1-5 rounds. The mined block reward is spread across those rounds. Each round deducts a 2-coin rental fee and a 1-coin maintenance fee. The application reports cumulative gross earnings, fees, and net profit, and warns whenever cumulative fees exceed cumulative earnings. These are illustrative simulation values rather than external market prices.

## 5. Security and Data Handling

Confirmed blocks are linked by each preceding block's SHA-256 hash and signed with the local ECDSA P-256 key. Proof-of-work difficulty is recorded in each new block and independently checked during validation. The pending pool is stored with confirmed entries in the extended text ledger format. The storage reader also accepts the original 10-field Formative 1 records, whose legacy payload and hash rules remain unchanged.

The librarian private key is stored under `keys/`; the existing authentication subsystem stores salted password hashes. Manual token transfers are intentionally session-only; confirmed return rewards are recoverable from the chain. The demo mining payouts are reported separately and are not added to student token balances.

## 6. Design Choices and Assumptions

- The assignment does not specify a calendar/time-zone rule for “on time”; the implementation uses the existing 14-day loan duration and compares elapsed timestamps.
- The transaction fee is 1 coin, deducted from a return reward or charged in addition to a manual transfer amount.
- Mining simulation reward is 2 coins per confirmed block. Pool fee is 2%; cloud rental and maintenance fees are 2 and 1 coins per round.
- Pool hash rates are generated randomly for each mining run, so the displayed distribution can differ between runs.
- The model, balances, nonce state, and transaction history are session-local except that return rewards can be rebuilt from confirmed blocks. Mining payout allocations are also session-local and credited only to registered member IDs selected for the run.

## 7. Test Results and Evidence

The project was built in WSL with GCC using `make` and the configured `-Wall -Wextra -Wpedantic` flags; the final build completed without warnings. The following interactive scenarios were exercised in isolated temporary working directories with difficulty 1. Results below are from those runs; unrun cases remain marked for follow-up.

| Scenario | Steps | Expected result | Actual result |
|---|---|---|---|
| Pending borrow | Borrow `BK001` for `ALU001`; view pending pool | Borrow appears pending; confirmed chain and balances do not change | **Passed:** appeared in pending pool and persisted; chain count unchanged. |
| Confirmed on-time return | Mine borrow; return same book within 14 days; mine return | Return block contains reward 10 and transaction ID; selected model credits 9 after fee | **Passed:** return had reward 10 and a SHA-256 transaction ID; UTXO member output was 9 and `SYSTEM` fee output was 1. |
| No reward for overdue | Queue overdue event and mine | Overdue block has reward 0 and no reward transaction | [Run and record] |
| Late return | Return after the configured loan period; mine | Return reward is 5; member receives 4 net coins | [Run and record] |
| Insufficient balance | Attempt transfer before the sender has amount plus fee | Transfer rejected; balances and UTXOs unchanged | [Run and record] |
| UTXO transfer and change | Transfer 5 coins from `ALU001` to `ALU002` with enough inputs | Recipient, fee, and change outputs appear | **Passed:** recipient 5, SYSTEM fee 1, change 5; sender/recipient balances became 7 and 5. A direct double-spend attempt was not separately exercised. |
| Invalid/reused nonce | In account mode transfer with nonce 1, then reuse nonce 1 | Valid outgoing transfer increments nonce; reused nonce is rejected | **Passed:** nonce 1 transfer succeeded; reused nonce 1 was rejected with expected nonce 2; balances and history matched. |
| Pool mining | Queue a borrow and mine with 2 members in the pool | Rewards use attempt shares after 2% fee | **Passed:** one run allocated 4 attempts as 2/2; gross 2.00, fee 0.04, net credits 0.98 each. |
| Unprofitable cloud rental | Mine one block over 1 round | Warning appears when fees exceed rewards; negative payout is not credited | **Passed:** gross 2.00, fees 3.00, net -1.00; warning displayed and no negative balance was applied. |
| Mining rewards | Mine borrow and return blocks using solo mining | Member receives simulated miner payout | **Passed:** selected member received 2.00 per confirmed block in both models. |
| Chain validation | Validate newly mined lending chain | Hashes, links, signatures, and PoW verify | **Passed:** account scenario reported `CHAIN VALID`. |

Still to exercise before submission: late return (5 nominal / 4 net), overdue notice creates no reward transaction, insufficient balance rejection, an explicit reused-UTXO attempt, a profitable cloud rental, and tamper detection. The pool's random rates mean its attempt split can vary between runs.
| Tamper detection | Modify a confirmed record with the tamper option | Chain validation reports a hash, link, or signature failure | [Run and record] |

Insert the following genuine application screenshots before submitting:

- **Figure 1:** Borrow event and pending pool.
- **Figure 2:** Mined confirmation, block reward/transaction ID, attempts, and valid signature.
- **Figure 3:** Updated balances and the complete UTXO set in UTXO mode.
- **Figure 4:** Account-based balance, nonce, successful/failed transfer, and member history.
- **Figure 5:** Pool miner contribution table.
- **Figure 6:** Cloud rounds with gross earnings, fees, net profit, and an unprofitable warning.
- **Figure 7:** Validation result for the intact chain and, optionally, tamper detection.

## 8. Conclusion

The extension connects library lending events to pending blockchain records, mining confirmation, and member reward transactions. It demonstrates two ways to represent token balances and three approaches to simulating mining rewards. The most important operational distinction is that pending events remain unconfirmed and do not affect member balances until proof-of-work adds them to the chain.
