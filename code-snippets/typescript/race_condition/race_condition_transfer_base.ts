// RACE CONDITIONS
// Prevents double-spend with optimistic locking — the update only
// succeeds if the row version hasn't changed since you read it.
// If someone else modified it first, the query affects 0 rows
// and we reject the transaction instead of silently double-spending.

async function transferFunds(
  db: any,
  fromId: string,
  toId: string,
  amount: number,
  version: number
): Promise<void> {
  if (amount <= 0) throw new Error("Amount must be positive");

  const result = await db.query(
    `UPDATE accounts SET balance = balance - $1, version = version + 1
     WHERE id = $2 AND version = $3 AND balance >= $1`,
    [amount, fromId, version]
  );

  if (result.rowCount === 0) {
    throw new Error("Transfer failed — stale version or insufficient balance");
  }

  await db.query(
    "UPDATE accounts SET balance = balance + $1, version = version + 1 WHERE id = $2",
    [amount, toId]
  );
}
