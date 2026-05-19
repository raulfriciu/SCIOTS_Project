import { writeFileSync } from 'fs';
import { RsaPublicKey, RsaPrivateKey, generateKeyPair } from './rsa.js';

const { publicKey, privateKey } = generateKeyPair(2048);

const publicKeyJson = {
  n: publicKey.n.toString(),
  e: publicKey.e.toString()
}

const privateKeyJson = {
  n: privateKey.n.toString(),
  d: privateKey.d.toString()
}

writeFileSync('rsa-public-key.json', JSON.stringify(publicKeyJson));

writeFileSync('rsa-private-key.json', JSON.stringify(privateKeyJson));