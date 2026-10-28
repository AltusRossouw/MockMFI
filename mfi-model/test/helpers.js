import { defaultPkiDirectory, ensureTestPki, loadTestAuthenticator } from '../src/pki.js';

export const pkiDirectory = ensureTestPki(defaultPkiDirectory());

export function auth(options = {}) {
  return loadTestAuthenticator(pkiDirectory, options);
}

export function withTimeout(promise, milliseconds = 3000, label = 'operation') {
  let timer;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => reject(new Error(`${label} timed out after ${milliseconds} ms`)), milliseconds);
  });
  return Promise.race([promise, timeout]).finally(() => clearTimeout(timer));
}
