import express from 'express';
import { generateKeyPair } from '../rsa/rsa.js';
import { generatePaillierKeyPair } from '../rsa/paillier.js';
import { modPow } from 'bigint-crypto-utils';

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

// State variables for Paillier verification/decryption flow
let pendingCiphertext = null;
let pendingSignature = null;
let signatureVerified = false;

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

// POST /paillier/receive - Receives signed ciphertext and stores it in the central vault
app.post('/paillier/receive', (req, res) => {
  const { ciphertext, signature } = req.body;
  console.log(`[HTTP POST] /paillier/receive - Signed sum received from Aggregator`);

  if (!ciphertext || !signature) {
    console.error('  Error: Missing ciphertext or signature in request body');
    return res.status(400).json({ error: 'Missing ciphertext or signature' });
  }

  try {
    pendingCiphertext = BigInt(ciphertext);
    pendingSignature = BigInt(signature);
    signatureVerified = false;
    console.log(`  Stored pending ciphertext and signature in Central Vault.`);
    res.json({
      success: true,
      message: 'Signed ciphertext received and stored in Central Vault'
    });
  } catch (e) {
    console.error('  Error storing pending ciphertext:', e.message);
    res.status(400).json({ error: 'Invalid format' });
  }
});

// POST /paillier/verify-signature - Verifies the signature of the stored ciphertext
app.post('/paillier/verify-signature', async (req, res) => {
  console.log(`[HTTP POST] /paillier/verify-signature - Request received`);

  if (pendingCiphertext === null || pendingSignature === null) {
    console.error('  Error: No pending signed ciphertext to verify');
    return res.status(400).json({ error: 'No pending signed ciphertext to verify' });
  }

  try {
    // 1. Fetch the Aggregator's public key
    console.log('  Fetching Aggregator RSA Public Key for signature verification...');
    const aggKeyResponse = await fetch('http://127.0.0.1:4000/rsa/key');
    if (!aggKeyResponse.ok) {
      throw new Error(`Failed to fetch Aggregator key: ${aggKeyResponse.statusText}`);
    }
    const { n: aggN, e: aggE } = await aggKeyResponse.json();
    const BigN = BigInt(aggN);
    const BigE = BigInt(aggE);
    console.log(`  Aggregator Public Key fetched: n = ${BigN.toString().substring(0, 40)}...`);

    // 2. Verify the Aggregator's RSA signature: c_verified = s^e mod n
    const cVerified = modPow(pendingSignature, BigE, BigN);
    console.log(`  Verifying signature s^e mod n == c_sum mod n_agg...`);
    
    if (cVerified !== (pendingCiphertext % BigN)) {
      console.error('  ❌ Signature verification failed! Unauthenticated Aggregator.');
      signatureVerified = false;
      return res.status(401).json({ error: 'Signature verification failed! Unauthenticated Aggregator.' });
    }

    signatureVerified = true;
    console.log('  ✅ Signature verified successfully! Ready for decryption.');
    res.json({
      success: true,
      verified: true,
      message: 'Signature verified successfully!'
    });
  } catch (e) {
    console.error('  Error during signature verification:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// POST /paillier/decrypt - Decrypts the stored ciphertext after signature has been verified
app.post('/paillier/decrypt', (req, res) => {
  console.log(`[HTTP POST] /paillier/decrypt - Request received`);

  if (pendingCiphertext === null) {
    console.error('  Error: No ciphertext available to decrypt');
    return res.status(400).json({ error: 'No ciphertext available to decrypt. Please submit data first.' });
  }

  if (!signatureVerified) {
    console.error('  Error: Signature must be verified before decryption!');
    return res.status(403).json({ error: 'Signature must be verified before decryption!' });
  }

  try {
    // 3. Decrypt the homomorphic sum
    console.log('  Decrypting consolidated sum using Paillier Private Key...');
    const sum = paillierPrivateKey.decrypt(pendingCiphertext);
    console.log(`  Decryption successful! Plaintext sum = ${sum}`);
    
    // Clear state
    pendingCiphertext = null;
    pendingSignature = null;
    signatureVerified = false;

    res.json({
      success: true,
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
