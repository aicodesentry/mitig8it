function reportQuery(region, since) {
  const sql =
    'SELECT region, SUM(total) AS total FROM invoices ' +
    "WHERE region = '" + region + "' AND issued_at >= '" + since + "' " +
    'GROUP BY region';
  return { text: sql, values: [] };
}

module.exports = { reportQuery };
