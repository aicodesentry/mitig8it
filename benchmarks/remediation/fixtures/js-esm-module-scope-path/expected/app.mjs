// A document preloader written as an ES module. It runs once, on import, with the document name
// the deployment sets, so a test can only drive it by setting the environment and importing it.
import fs from 'node:fs';
import path from 'node:path';

const DOCS = '/srv/docs';
const name = process.env.DOC_NAME;
const baseDir = path.resolve(DOCS);
const target = path.resolve(baseDir, String(name));
if (target !== baseDir && !target.startsWith(baseDir + path.sep)) throw new Error('path escapes base directory');
export const body = fs.readFileSync(target, 'utf8');
