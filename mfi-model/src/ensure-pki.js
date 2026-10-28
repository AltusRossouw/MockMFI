import { ensureTestPki, defaultPkiDirectory } from './pki.js';

const directory = ensureTestPki(defaultPkiDirectory());
console.log(`test PKI ready: ${directory}`);
