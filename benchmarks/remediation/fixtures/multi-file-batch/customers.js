// Normalizes the customer email that the order lookup places into its SQL filter.
function normalizeEmail(email) {
  return String(email);
}

module.exports = { normalizeEmail };
