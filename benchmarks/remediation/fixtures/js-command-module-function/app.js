const { exec } = require('child_process');

function renderReport(name, callback) {
  return exec(`wkhtmltopdf ${name} report.pdf`, callback);
}

module.exports = { renderReport };
