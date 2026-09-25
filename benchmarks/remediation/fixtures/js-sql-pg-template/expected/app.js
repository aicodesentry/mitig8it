const BASE_QUERY = 'SELECT id, sku, price FROM products';

function buildProductSearch(term, limit) {
  return {
    text: `${BASE_QUERY} WHERE sku LIKE $1 ORDER BY sku LIMIT $2`,
    values: [`%${term}%`, Number(limit) || 25],
  };
}

module.exports = { buildProductSearch, BASE_QUERY };
