class CustomerStore {
  constructor(db) {
    this.db = db;
  }

  findByEmail(email) {
    return this.db.query('SELECT id FROM customers WHERE email = $1', [email]);
  }
}

module.exports = { CustomerStore };
