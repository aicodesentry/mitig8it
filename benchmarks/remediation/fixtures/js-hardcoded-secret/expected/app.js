// Client for the vendor billing API.
const apiKey = process.env.API_KEY;

function authHeaders() {
  return { Authorization: `Bearer ${apiKey}` };
}

module.exports = { apiKey, authHeaders };
