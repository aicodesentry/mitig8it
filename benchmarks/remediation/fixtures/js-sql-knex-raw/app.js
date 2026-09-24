// Ledger reads through the knex query builder's raw() escape hatch.
// Two statements in this file place the account id straight into SQL text.
function accountEntries(db, accountId) {
  return db.raw(`SELECT id, amount FROM entries WHERE account_id = '${accountId}'`);
}

function accountBalance(db, accountId) {
  return db.raw("SELECT SUM(amount) AS balance FROM entries WHERE account_id = '" + accountId + "'");
}

module.exports = { accountEntries, accountBalance };
