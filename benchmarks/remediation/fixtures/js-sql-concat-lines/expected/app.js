function reportQuery(region, since) {
  const sql =
    'SELECT region, SUM(total) AS total FROM invoices ' +
    'WHERE region = $1 AND issued_at >= $2 ' +
    'GROUP BY region';
  return { text: sql, values: [region, since] };
}

module.exports = { reportQuery };
