const vm = require('vm');

const DISCOUNT_RULE = 'price > 100 ? price * 0.9 : price';

function applyDiscount(price) {
  const amount = Number(price);
  if (!Number.isFinite(amount)) {
    throw new TypeError('price must be a number');
  }
  return vm.runInNewContext(DISCOUNT_RULE, { price: amount });
}

module.exports = { applyDiscount };
