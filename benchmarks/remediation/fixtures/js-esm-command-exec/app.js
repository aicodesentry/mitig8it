// A backup helper written as an ES module, with the child_process call bound by a named import.
import { exec } from 'node:child_process';

export function archive(directory, callback) {
  exec(`tar -czf /backups/archive.tgz ${directory}`, callback);
}
