// Pricing rules evaluated per request.
function applyRule(body, row) {
  const expression = body.expression;
  return eval(expression);
}

module.exports = { applyRule };
