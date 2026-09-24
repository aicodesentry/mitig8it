const { exec, execFile } = require('child_process');

function renderReport(name, callback) {
  return execFile('wkhtmltopdf', [name, 'report.pdf'], callback);
}

module.exports = { renderReport };
