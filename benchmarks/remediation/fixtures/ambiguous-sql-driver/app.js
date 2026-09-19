function runUnknownAdapter(db, userInput) {
  return db.execute(`select * from users where email = '${userInput}'`);
}

module.exports = { runUnknownAdapter };
