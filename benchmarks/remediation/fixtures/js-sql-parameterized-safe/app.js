// Account lookups. The statement is already parameterized for the pg driver.
function buildAccountLookup(accountNumber) {
  return {
    text: 'SELECT id, owner, balance FROM accounts WHERE account_number = $1',
    values: [accountNumber],
  };
}

module.exports = { buildAccountLookup };
