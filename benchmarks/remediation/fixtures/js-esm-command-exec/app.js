// A backup helper written as an ES module, with the child_process call bound by a named import.
import { exec } from 'node:child_process';

export function archive(name, callback) {
  exec(`tar -czf /backups/${name}.tgz /srv/data`, callback);
}
