function auditReport(filter) {
  return `audit-tool | grep ${filter} | formatter`;
}

module.exports = { auditReport };
