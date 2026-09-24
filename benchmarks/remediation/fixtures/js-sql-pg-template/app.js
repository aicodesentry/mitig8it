const BASE_QUERY = 'SELECT id, sku, price FROM products';

function buildProductSearch(term, limit) {
  return {
    text: `${BASE_QUERY} WHERE sku LIKE '%${term}%' ORDER BY sku LIMIT ${Number(limit) || 25}`,
    values: [],
  };
}

module.exports = { buildProductSearch, BASE_QUERY };
