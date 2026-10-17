const vm = require('vm');

// The expression is fixed at build time; nothing from a request reaches it.
const SESSION_TTL_EXPRESSION = 'Math.max(15, 30) * 60';

function sessionTtlSeconds() {
  const context = vm.createContext({ Math });
  return vm.runInContext(SESSION_TTL_EXPRESSION, context);
}

module.exports = { sessionTtlSeconds };
