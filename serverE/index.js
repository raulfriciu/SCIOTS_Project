import express from 'express';
import { generatePaillierKeyPair } from '../rsa/paillier.js';
import { modPow } from 'bigint-crypto-utils';

const app = express();
app.use(express.json());

console.log('=== Compañía Eléctrica / Utility Server (serverE) Starting ===');

// Generate Paillier Keypair on startup
console.log('Generating Paillier Keypair (1024 bits)...');
const { publicKey: paillierPublicKey, privateKey: paillierPrivateKey } = generatePaillierKeyPair(1024);
console.log('Paillier Keypair generated successfully!');

// State: signed ciphertext received from the aggregator
let pendingCiphertext = null;   // BigInt
let pendingSignature  = null;   // BigInt
let signatureVerified = false;

// ─────────────────────────────────────────────────────────────────────────────
// GET /paillier/key
// Returns the Paillier public key (n, g).
// Smart meters fetch this to encrypt their readings.
// ─────────────────────────────────────────────────────────────────────────────
app.get('/paillier/key', (req, res) => {
  console.log(`[HTTP GET] /paillier/key`);
  res.json({
    n: paillierPublicKey.n.toString(),
    g: paillierPublicKey.g.toString()
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// POST /paillier/receive
// Receives the aggregated+signed ciphertext from the aggregator.
// Body: { ciphertext: string, signature: string }
// ─────────────────────────────────────────────────────────────────────────────
app.post('/paillier/receive', (req, res) => {
  const { ciphertext, signature } = req.body;
  console.log(`[HTTP POST] /paillier/receive — Signed sum received from Aggregator`);

  if (!ciphertext || !signature) {
    return res.status(400).json({ error: 'Missing ciphertext or signature' });
  }

  try {
    pendingCiphertext = BigInt(ciphertext);
    pendingSignature  = BigInt(signature);
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

// ─────────────────────────────────────────────────────────────────────────────
// POST /paillier/verify-signature
// Fetches the aggregator's RSA public key and verifies the signature
// of the stored ciphertext. Must succeed before /paillier/decrypt is allowed.
// ─────────────────────────────────────────────────────────────────────────────
app.post('/paillier/verify-signature', async (req, res) => {
  console.log(`[HTTP POST] /paillier/verify-signature`);

  if (pendingCiphertext === null || pendingSignature === null) {
    return res.status(400).json({ error: 'No pending signed ciphertext to verify' });
  }

  try {
    // Fetch the aggregator's RSA public key (the aggregator generated its own keypair)
    console.log('  Fetching Aggregator RSA Public Key from http://127.0.0.1:4000/rsa/key ...');
    const aggKeyResponse = await fetch('http://127.0.0.1:4000/rsa/key');
    if (!aggKeyResponse.ok) {
      throw new Error(`Failed to fetch Aggregator RSA key: ${aggKeyResponse.statusText}`);
    }
    const { n: aggN, e: aggE } = await aggKeyResponse.json();
    const BigN = BigInt(aggN);
    const BigE = BigInt(aggE);
    console.log(`  Aggregator public key: n = ${BigN.toString().substring(0, 40)}...`);

    // Verify: s^e mod n_agg  ===  c_sum mod n_agg
    const cVerified = modPow(pendingSignature, BigE, BigN);
    if (cVerified !== (pendingCiphertext % BigN)) {
      signatureVerified = false;
      console.error('  ❌ Signature verification FAILED — unauthenticated aggregator.');
      return res.status(401).json({
        error: 'Signature verification failed! Unauthenticated Aggregator.'
      });
    }

    signatureVerified = true;
    console.log('  ✅ Signature verified — aggregator is authenticated. Ready to decrypt.');
    res.json({
      success:  true,
      verified: true,
      message:  'Aggregator signature verified successfully!'
    });
  } catch (e) {
    console.error('  Error during verification:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// POST /paillier/decrypt
// Decrypts the stored aggregated ciphertext using the Paillier private key.
// Requires that /paillier/verify-signature has passed first.
// ─────────────────────────────────────────────────────────────────────────────
app.post('/paillier/decrypt', (req, res) => {
  console.log(`[HTTP POST] /paillier/decrypt`);

  if (pendingCiphertext === null) {
    return res.status(400).json({ error: 'No ciphertext available. Submit data first.' });
  }
  if (!signatureVerified) {
    return res.status(403).json({ error: 'Signature must be verified before decryption!' });
  }

  try {
    console.log('  Decrypting consolidated sum using Paillier private key...');
    const sum = paillierPrivateKey.decrypt(pendingCiphertext);
    console.log(`  ✅ Decryption successful! Plaintext sum = ${sum}`);

    // Clear state
    pendingCiphertext = null;
    pendingSignature  = null;
    signatureVerified = false;

    res.json({ success: true, decrypted: sum.toString() });
  } catch (e) {
    console.error('  Error decrypting:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
const PORT = 3000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Utility Server (Compañía Eléctrica) running on http://0.0.0.0:${PORT}`);
  console.log('Endpoints:');
  console.log('  GET  /paillier/key              → Paillier public key (for meters to encrypt)');
  console.log('  POST /paillier/receive          → receives signed aggregated ciphertext');
  console.log('  POST /paillier/verify-signature → verifies aggregator RSA signature');
  console.log('  POST /paillier/decrypt          → decrypts sum (after signature verified)');
  console.log('======================================================');
});
