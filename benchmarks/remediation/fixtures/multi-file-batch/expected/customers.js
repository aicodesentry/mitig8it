// Normalizes the customer email that the order lookup places into its SQL filter.
const EMAIL = /^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$/;

function normalizeEmail(email) {
  const value = String(email);
  if (!EMAIL.test(value)) {
    throw new TypeError('customer email is not a valid address');
  }
  return value;
}

module.exports = { normalizeEmail };
