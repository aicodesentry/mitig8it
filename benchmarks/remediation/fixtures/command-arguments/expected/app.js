function buildArchiveCommand(filename) {
  return ['tar', '-cf', 'archive.tar', '--', filename];
}

module.exports = { buildArchiveCommand };
