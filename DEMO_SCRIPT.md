# Formative 2 Demo Script (5-10 Minutes)

## Before Recording

1. Build in WSL/MSYS2 with GCC, Make, and OpenSSL installed: `make`.
2. Use a clean demo ledger if you do not need existing records. Back up any data you want to keep before running `make reset`; this command deletes the local ledger, keys, and authentication file.
3. Launch `./library_chain --model utxo --difficulty 2` and sign in as `librarian` with the configured password. For account features, restart with `--model account` after the UTXO demonstration.
4. Keep `books.txt` and `members.txt` in the application working directory. Example IDs are `BK001`, `ALU001`, and `ALU002`.

## Recording Outline

### 0:00-0:45 - Introduce the system

Show the application banner, selected token model, difficulty, and menu. Explain that borrow and return events go to a pending pool first; only mining confirms them and updates reward balances.

**Capture:** startup menu showing model and difficulty.

### 0:45-2:00 - Pending borrow

Choose option `1`, enter `BK001` and `ALU001`. Show that the event is queued rather than confirmed. Choose option `11` to show the pending pool. Option `5` can show the pending loan state.

**Capture:** pending pool containing the borrow event.

### 2:00-3:15 - Mine and return

Choose option `12`, choose solo mining (`1`), and enter a registered member ID as the miner payout recipient. Show the nonce/hash attempts. The borrow block should confirm without a library return reward, while the miner receives the separate mining payout. Choose option `2` and return `BK001` for `ALU001`, then show the pending return and its reward transaction ID. Choose option `12`, mine again, and enter the payout recipient.

**Capture:** confirmed return record showing timestamp, reward, transaction ID, hash attempts, and signature status. Capture option `13` balances and option `14` full UTXO set.

### 3:15-4:30 - UTXO transfer behavior

Use a member who has a return or mining reward as the sender and another registry member as recipient. Choose option `15` and transfer an amount smaller than the sender's available balance. Show the recipient output, fee output, and change output in option `14`. Attempt a second transfer that exceeds the remaining balance and show that it is rejected without spending outputs.

**Capture:** UTXO set after a transfer, including fee and change outputs; insufficient-balance message.

### 4:30-6:00 - Pool mining

Queue another borrow and return pair, then mine from option `12` using pool mining (`2`). Select 2-4 miners and enter a registered member ID for each payout. Show the randomized hash rates, allocated attempts, contribution shares, 2% pool fee, rewards, and credited balances.

**Capture:** pool mining reward-sharing table.

### 6:00-7:00 - Cloud mining

Queue one or more events and select cloud mining (`3`) with a rental duration from 1 to 5 rounds and a registered member ID for the payout. Show round earnings, rental and maintenance fees, cumulative net profit, the warning if cumulative fees exceed rewards, and any positive net credit.

**Capture:** cloud mining round table and unprofitable warning when shown.

### 7:00-8:30 - Account model and validation

Restart as `./library_chain --model account --difficulty 2`. Repeat a confirmed return if needed to create a balance. Use option `15` with the sender's next nonce, then option `16` for that member's history. Retry with an incorrect or reused nonce to show rejection. Use option `13` to show balance and nonce. Finally, use option `4` to validate the chain.

**Capture:** account balance/nonce, transaction history, rejected nonce, and `CHAIN VALID` output.

## Submission Checklist

- Keep the screen readable and briefly narrate the pending-versus-confirmed distinction.
- Include the genuine screenshots listed above in the technical report; do not use mock output.
- Replace any altered default credentials in your own local setup before recording, and do not show private key contents.
- If time is short, prioritize pending pool, confirmed return reward, balance/UTXO update, pool table, cloud warning, and account nonce/history.
