// Vendor billing client.
const API_KEY = process.env.API_KEY;

function vendorHeaders(requestId) {
  return {
    Authorization: `Bearer ${API_KEY}`,
    'Content-Type': 'application/json',
    'X-Request-Id': String(requestId),
  };
}

module.exports = { vendorHeaders, API_KEY };
