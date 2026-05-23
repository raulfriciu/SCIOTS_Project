import express from 'express';

const app = express();
app.use(express.json());

console.log('=== Homomorphic Aggregator Server (aggregator) Starting ===');

// In-memory storage for ciphertexts submitted by clients
let ciphertextBuffer = [];

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
// Aggregates stored ciphertexts, sends the resulting c_sum to serverE, and returns the decrypted sum
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

    // 3. Send c_sum to the decryption server (serverE)
    console.log('  Sending aggregated ciphertext c_sum to Decryption Server for decryption...');
    const decryptResponse = await fetch('http://127.0.0.1:3000/paillier/decrypt', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        ciphertext: cSum.toString()
      })
    });

    if (!decryptResponse.ok) {
      throw new Error(`Decryption Server failed to decrypt: ${decryptResponse.statusText}`);
    }

    const { decrypted } = await decryptResponse.json();
    console.log(`  Decryption Server returned plaintext sum: ${decrypted}`);

    // Clear buffer after successful aggregation
    const finalCount = ciphertextBuffer.length;
    ciphertextBuffer = [];
    console.log('  Ciphertext buffer cleared.');

    res.json({
      message: 'Homomorphic aggregation successful',
      aggregatedCount: finalCount,
      ciphertextSum: cSum.toString(),
      decryptedSum: decrypted
    });

  } catch (e) {
    console.error('  Error during homomorphic aggregation:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// Endpoint: POST /paillier/reset
// Resets the ciphertext buffer manually
app.post('/paillier/reset', (req, res) => {
  console.log(`[HTTP POST] /paillier/reset - Request received`);
  ciphertextBuffer = [];
  console.log('  Ciphertext buffer manually cleared.');
  res.json({ message: 'Buffer cleared' });
});

// Start listening
const PORT = 4000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Homomorphic Aggregator Server running on http://0.0.0.0:${PORT}`);
  console.log('======================================================');
});
