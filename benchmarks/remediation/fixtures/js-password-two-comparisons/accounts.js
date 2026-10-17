'use strict';
const crypto = require('crypto');

function encryptPassword(password) {
  return crypto.createHash('sha1').update(password).digest('hex');
}

function login(account, password) {
  return encryptPassword(password) == account.password;
}

function changePassword(account, current, next) {
  if (encryptPassword(current) != account.password) {
    throw new Error('current password does not match');
  }
  account.password = encryptPassword(next);
  return account;
}

module.exports = { encryptPassword, login, changePassword };
