function loadOrder(db, reference) {
  return db.query(`SELECT id, total FROM orders WHERE reference = '${reference}'`);
}

module.exports = { loadOrder };
