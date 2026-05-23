import express from 'express';
import { generateKeyPair } from '../rsa/rsa.js';

const app = express();
app.use(express.json());

console.log('=== Homomorphic Aggregator Server (aggregator) Starting ===');

// Generate Aggregator's own RSA keypair for signing consolidated data
console.log('Generating Aggregator RSA Keypair (1024 bits)...');
const { publicKey: aggRsaPublicKey, privateKey: aggRsaPrivateKey } = generateKeyPair(1024);
console.log('Aggregator RSA Keypair generated successfully!');

// In-memory storage for ciphertexts submitted by clients
let ciphertextBuffer = [];
// Store the latest aggregated ciphertext sum
let latestCiphertextSum = null;

// Endpoint: GET /rsa/key - Returns Aggregator's RSA Public Key
app.get('/rsa/key', (req, res) => {
  console.log(`[HTTP GET] /rsa/key - Request received`);
  res.json({
    n: aggRsaPublicKey.n.toString(),
    e: aggRsaPublicKey.e.toString()
  });
});

// Endpoint: POST /paillier/submit
// Receives a ciphertext from a client and stores it in memory
app.post('/paillier/submit', (req, res) => {
  const { ciphertext } = req.body;
  console.log(`[HTTP POST] /paillier/submit - Request received`);

  if (!ciphertext) {
    console.error('  Error: Missing ciphertext in request body');
    return res.status(400).json({ error: 'Missing ciphertext' });
  }

  try {
    const c = BigInt(ciphertext);
    ciphertextBuffer.push(c);
    console.log(`  Successfully added ciphertext to buffer. Current buffer size: ${ciphertextBuffer.length}`);
    console.log(`  Added: c = ${c.toString().substring(0, 40)}...`);

    res.json({
      message: 'Ciphertext stored successfully',
      bufferSize: ciphertextBuffer.length
    });
  } catch (e) {
    console.error('  Error processing ciphertext:', e.message);
    res.status(400).json({ error: 'Invalid ciphertext format' });
  }
});

// Endpoint: POST /paillier/aggregate
// ONLY packages (multiplies) all stored ciphertexts homomorphically. DOES NOT decrypt yet!
app.post('/paillier/aggregate', async (req, res) => {
  console.log(`[HTTP POST] /paillier/aggregate - Request received`);

  if (ciphertextBuffer.length === 0) {
    console.error('  Error: No ciphertexts in buffer to aggregate');
    return res.status(400).json({ error: 'No ciphertexts in buffer. Submit some first!' });
  }

  try {
    // 1. Fetch the Paillier public key n from the decryption server (serverE)
    console.log('  Fetching Paillier public key n from Decryption Server...');
    const keyResponse = await fetch('http://127.0.0.1:3000/paillier/key');
    if (!keyResponse.ok) {
      throw new Error(`Failed to fetch Paillier key from serverE: ${keyResponse.statusText}`);
    }
    const { n } = await keyResponse.json();
    const BigN = BigInt(n);
    const BigN2 = BigN * BigN;
    console.log(`  Decryption Server public key fetched: n = ${BigN.toString().substring(0, 40)}...`);

    // 2. Perform homomorphic addition: multiply all ciphertexts modulo n^2
    console.log(`  Performing homomorphic addition on ${ciphertextBuffer.length} ciphertexts...`);
    let cSum = 1n;
    for (const c of ciphertextBuffer) {
      cSum = (cSum * c) % BigN2;
    }
    console.log(`  Aggregated ciphertext: c_sum = ${cSum.toString().substring(0, 40)}...`);

    // Store in memory for the next step (signing and sending)
    latestCiphertextSum = cSum;
    const finalCount = ciphertextBuffer.length;
    ciphertextBuffer = []; // Clear buffer
    console.log('  Ciphertext buffer cleared.');

    res.json({
      message: 'Homomorphic aggregation (packaging) successful',
      aggregatedCount: finalCount,
      ciphertextSum: cSum.toString()
    });

  } catch (e) {
    console.error('  Error during homomorphic aggregation:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// Endpoint: POST /paillier/sign-and-send
// Signs the latest aggregated ciphertext sum and sends it to serverE for verified decryption
app.post('/paillier/sign-and-send', async (req, res) => {
  console.log(`[HTTP POST] /paillier/sign-and-send - Request received`);

  if (latestCiphertextSum === null) {
    console.error('  Error: No aggregated ciphertext sum in memory. Run /aggregate first.');
    return res.status(400).json({ error: 'No aggregated sum available. Aggregate first!' });
  }

  try {
    // 1. Sign the aggregated ciphertext sum: s = (c_sum)^d mod n
    console.log('  Signing aggregated ciphertext sum with Aggregator private key...');
    const signature = aggRsaPrivateKey.sign(latestCiphertextSum);
    console.log(`  Signature generated: s = ${signature.toString().substring(0, 40)}...`);

    // 2. Send both ciphertext and signature to the central decryption server (serverE)
    console.log('  Sending signed ciphertext to Decryption Server for storage...');
    const decryptResponse = await fetch('http://127.0.0.1:3000/paillier/receive', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        ciphertext: latestCiphertextSum.toString(),
        signature: signature.toString()
      })
    });

    if (!decryptResponse.ok) {
      const errData = await decryptResponse.json();
      throw new Error(`Decryption Server error: ${errData.error || decryptResponse.statusText}`);
    }

    console.log('  Decryption Server successfully received and stored the signed sum.');

    const resolvedSum = latestCiphertextSum;
    latestCiphertextSum = null; // Clear from memory

    res.json({
      message: 'Aggregation signature successfully sent to Central',
      ciphertextSum: resolvedSum.toString(),
      signature: signature.toString()
    });

  } catch (e) {
    console.error('  Error during sign-and-send flow:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// Endpoint: POST /paillier/reset
// Resets the ciphertext buffer manually
app.post('/paillier/reset', (req, res) => {
  console.log(`[HTTP POST] /paillier/reset - Request received`);
  ciphertextBuffer = [];
  latestCiphertextSum = null;
  console.log('  Ciphertext buffer manually cleared.');
  res.json({ message: 'Buffer cleared' });
});

// Start listening
const PORT = 4000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Homomorphic Aggregator Server running on http://0.0.0.0:${PORT}`);
  console.log('======================================================');
});
