'use strict';

const res = Object.create(require('http').ServerResponse.prototype);

// The framework's own redirect helper. Callers decide the target; this
// definition only sets the status, the Location header and a short body.
res.redirect = function redirect(url) {
  let address = url;
  let status = 302;

  if (arguments.length === 2) {
    status = arguments[0];
    address = arguments[1];
  }

  this.statusCode = status;
  this.setHeader('Location', address);
  this.end('Redirecting to ' + encodeURI(address));
};

module.exports = res;
