function loadOrder(db, reference) {
  return db.query('SELECT id, total FROM orders WHERE reference = $1', [reference]);
}

module.exports = { loadOrder };
