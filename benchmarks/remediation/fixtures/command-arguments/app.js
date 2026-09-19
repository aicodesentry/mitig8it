function buildArchiveCommand(filename) {
  return ['sh', '-c', `tar -cf archive.tar ${filename}`];
}

module.exports = { buildArchiveCommand };
