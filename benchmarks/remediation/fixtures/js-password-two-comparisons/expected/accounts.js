'use strict';
const crypto = require('crypto');

function encryptPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  return ['scrypt', salt, crypto.scryptSync(password, salt, 32).toString('hex')].join('$');
}

function verifyPasswordHash(password, stored) {
  const [scheme, salt, expected] = String(stored).split('$');
  if (scheme !== 'scrypt' || !salt || !expected) return false;
  const actual = crypto.scryptSync(password, salt, 32);
  const wanted = Buffer.from(expected, 'hex');
  return wanted.length === actual.length && crypto.timingSafeEqual(actual, wanted);
}

function login(account, password) {
  return verifyPasswordHash(password, account.password);
}

function changePassword(account, current, next) {
  if (!verifyPasswordHash(current, account.password)) {
    throw new Error('current password does not match');
  }
  account.password = encryptPassword(next);
  return account;
}

module.exports = { encryptPassword, login, changePassword };
