// Runtime configuration for the payments integration.
const config = {
  baseUrl: 'https://payments.example.com',
  timeoutMs: 5000,
  clientSecret: process.env.CLIENT_SECRET,
};

function authorization() {
  return `Basic ${Buffer.from(`payments:${config.clientSecret}`).toString('base64')}`;
}

module.exports = { config, authorization };
