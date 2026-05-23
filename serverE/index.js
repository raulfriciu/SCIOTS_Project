import express from 'express';
import { generateKeyPair } from '../rsa/rsa.js';
import { generatePaillierKeyPair } from '../rsa/paillier.js';

const app = express();
app.use(express.json());

console.log('=== Decryption & Signature Server (serverE) Starting ===');

// 1. Generate RSA Keypair
console.log('Generating RSA Keypair (1024 bits)...');
const { publicKey: rsaPublicKey, privateKey: rsaPrivateKey } = generateKeyPair(1024);
console.log('RSA Keypair generated successfully!');

// 2. Generate Paillier Keypair
console.log('Generating Paillier Keypair (1024 bits)...');
const { publicKey: paillierPublicKey, privateKey: paillierPrivateKey } = generatePaillierKeyPair(1024);
console.log('Paillier Keypair generated successfully!');

// --- RSA Blind Signature Endpoints ---

// GET /rsa/key - Returns RSA Public Key
app.get('/rsa/key', (req, res) => {
  console.log(`[HTTP GET] /rsa/key - Request received`);
  res.json({
    n: rsaPublicKey.n.toString(),
    e: rsaPublicKey.e.toString()
  });
});

// POST /rsa/sign - Signs a blinded message
app.post('/rsa/sign', (req, res) => {
  const { blindedMessage } = req.body;
  console.log(`[HTTP POST] /rsa/sign - Request received`);
  
  if (!blindedMessage) {
    console.error('  Error: Missing blindedMessage in request body');
    return res.status(400).json({ error: 'Missing blindedMessage' });
  }

  try {
    const mBlind = BigInt(blindedMessage);
    console.log(`  Blinded message received: m' = ${mBlind.toString().substring(0, 40)}...`);
    
    // Sign the blinded message: s' = (m')^d mod n
    const sBlind = rsaPrivateKey.sign(mBlind);
    console.log(`  Blinded signature generated: s' = ${sBlind.toString().substring(0, 40)}...`);
    
    res.json({
      signature: sBlind.toString()
    });
  } catch (e) {
    console.error('  Error signing blinded message:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// --- Paillier Homomorphic Endpoints ---

// GET /paillier/key - Returns Paillier Public Key
app.get('/paillier/key', (req, res) => {
  console.log(`[HTTP GET] /paillier/key - Request received`);
  res.json({
    n: paillierPublicKey.n.toString(),
    g: paillierPublicKey.g.toString()
  });
});

// POST /paillier/decrypt - Decrypts ciphertext (representing aggregated sum)
app.post('/paillier/decrypt', (req, res) => {
  const { ciphertext } = req.body;
  console.log(`[HTTP POST] /paillier/decrypt - Request received`);

  if (!ciphertext) {
    console.error('  Error: Missing ciphertext in request body');
    return res.status(400).json({ error: 'Missing ciphertext' });
  }

  try {
    const c = BigInt(ciphertext);
    console.log(`  Ciphertext to decrypt: c_sum = ${c.toString().substring(0, 40)}...`);
    
    // Decrypt the homomorphic sum
    const sum = paillierPrivateKey.decrypt(c);
    console.log(`  Decryption successful! Plaintext sum = ${sum}`);
    
    res.json({
      decrypted: sum.toString()
    });
  } catch (e) {
    console.error('  Error decrypting ciphertext:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// Start listening
const PORT = 3000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Decryption & Signature Server running on http://0.0.0.0:${PORT}`);
  console.log('======================================================');
});
