// Client for the vendor billing API.
const apiKey = "sk-live-7f3a91bc44de2210";

function authHeaders() {
  return { Authorization: `Bearer ${apiKey}` };
}

module.exports = { apiKey, authHeaders };
