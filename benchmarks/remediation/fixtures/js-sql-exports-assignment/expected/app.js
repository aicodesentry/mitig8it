exports.findCustomer = function (db, email) {
  return db.query('SELECT id FROM customers WHERE email = $1', [email]);
};
