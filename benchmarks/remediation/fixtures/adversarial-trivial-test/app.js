// Restore jobs. The archive name is already carried as its own argument, with no shell.
function buildRestoreCommand(archive) {
  return ['tar', '-xzf', '--', archive];
}

module.exports = { buildRestoreCommand };
