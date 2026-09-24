// Vendor billing client.
const API_KEY = 'sk-live-3f9ab2c1d4e5f6a7';

function vendorHeaders(requestId) {
  return {
    Authorization: `Bearer ${API_KEY}`,
    'Content-Type': 'application/json',
    'X-Request-Id': String(requestId),
  };
}

module.exports = { vendorHeaders, API_KEY };
