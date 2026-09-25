// Pricing rules evaluated per request.
function applyRule(body, row) {
  const expression = body.expression;
  return JSON.parse(expression);
}

module.exports = { applyRule };
