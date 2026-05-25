import express from 'express';
import { coapGet, coapPost } from '../client/coap_client_wrapper.js';
import { PaillierPublicKey } from '../rsa/paillier.js';

const app = express();
app.use(express.json());

console.log('=== Smart Meters Service Starting ===');

// PSK credentials for CoAP (same as client)
const PSK_USER = 'clientA';
const PSK_KEY  = 'EiAT3eboMqOa0ddtwsiX57JUBnw08ClON7wLR7n8N2M=';

// Cached Paillier public key (fetched from utility on first use)
let cachedPaillierKey = null;      // { n: BigInt, g: BigInt }
let cachedPaillierKeyStr = null;   // { n: string, g: string } for JSON responses

// Initial meter readings (dashboard can update these)
const meterValues = { 1: 15, 2: 27, 3: 42 };

// Fetch the Paillier public key from the utility (serverE) via CoAP proxy
async function fetchPaillierKey(isSecure = false) {
  const port     = isSecure ? 5684 : 5683;
  const protocol = isSecure ? 'coaps' : 'coap';
  const url      = `${protocol}://127.0.0.1:${port}/paillier/key`;

  console.log(`[meters] Fetching Paillier public key from utility via ${url} ...`);
  const data = await coapGet(url, isSecure, PSK_USER, PSK_KEY);

  if (!data || !data.n || !data.g) {
    throw new Error('Could not fetch Paillier public key from utility. Is serverE and the CoAP proxy running?');
  }

  cachedPaillierKey    = new PaillierPublicKey(BigInt(data.n), BigInt(data.g));
  cachedPaillierKeyStr = { n: data.n, g: data.g };
  console.log(`[meters] Paillier public key loaded: n = ${data.n.substring(0, 40)}...`);
  return cachedPaillierKey;
}

// ─────────────────────────────────────────────────────────────────────────────
// Endpoint: POST /meter/:id/send
// Called by the dashboard when user clicks "Enviar Cifrado".
// Body: { value: number, isSecure: boolean }
// The meter:
//   1. Fetches the utility's Paillier public key (cached after first call)
//   2. Encrypts the value locally with that public key
//   3. Sends the ciphertext to the aggregator via CoAP proxy
// ─────────────────────────────────────────────────────────────────────────────
app.post('/meter/:id/send', async (req, res) => {
  const meterId  = parseInt(req.params.id);
  const { value, isSecure = false } = req.body;

  if (![1, 2, 3].includes(meterId)) {
    return res.status(400).json({ error: `Invalid meter id: ${meterId}. Must be 1, 2 or 3.` });
  }

  const numValue = Number(value);
  if (!Number.isFinite(numValue) || numValue <= 0) {
    return res.status(400).json({ error: 'Invalid value — must be a positive number.' });
  }

  console.log(`[Meter ${meterId}] Preparing to send: value = ${numValue} kWh (isSecure: ${isSecure})`);

  try {
    // Step 1: Ensure we have the Paillier public key
    if (!cachedPaillierKey) {
      await fetchPaillierKey(isSecure);
    }

    // Step 2: Encrypt the value locally using the utility's public key
    const ciphertext = cachedPaillierKey.encrypt(BigInt(numValue));
    console.log(`[Meter ${meterId}] Encrypted: c = ${ciphertext.toString().substring(0, 40)}...`);

    // Step 3: Submit ciphertext to aggregator via CoAP proxy
    const aggPort    = isSecure ? 5686 : 5685;
    const protocol   = isSecure ? 'coaps' : 'coap';
    const submitUrl  = `${protocol}://127.0.0.1:${aggPort}/paillier/submit`;

    console.log(`[Meter ${meterId}] Submitting ciphertext to aggregator via ${submitUrl} ...`);
    const aggResponse = await coapPost(
      submitUrl,
      { ciphertext: ciphertext.toString() },
      isSecure,
      PSK_USER,
      PSK_KEY
    );

    console.log(`[Meter ${meterId}] Aggregator response: ${aggResponse.message} (buffer: ${aggResponse.bufferSize})`);

    res.json({
      success:    true,
      meterId,
      value:      numValue,
      ciphertext: ciphertext.toString(),
      n:          cachedPaillierKeyStr.n,
      g:          cachedPaillierKeyStr.g,
      bufferSize: aggResponse.bufferSize
    });

  } catch (err) {
    console.error(`[Meter ${meterId}] Error: ${err.message}`);
    res.status(500).json({ success: false, error: err.message });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// Endpoint: GET /paillier-key
// Returns the cached Paillier public key (or fetches it on demand).
// Used by the dashboard to display n in the key vault.
// ─────────────────────────────────────────────────────────────────────────────
app.get('/paillier-key', async (req, res) => {
  const isSecure = req.query.isSecure === 'true';
  try {
    if (!cachedPaillierKey) {
      await fetchPaillierKey(isSecure);
    }
    res.json(cachedPaillierKeyStr);
  } catch (err) {
    res.status(503).json({ error: err.message });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// Endpoint: GET /status
// Simple health check.
// ─────────────────────────────────────────────────────────────────────────────
app.get('/status', (req, res) => {
  res.json({
    online: true,
    keyLoaded: !!cachedPaillierKey
  });
});

// ─────────────────────────────────────────────────────────────────────────────
const PORT = 6000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Smart Meters Service running on http://0.0.0.0:${PORT}`);
  console.log('Endpoints:');
  console.log('  POST /meter/:id/send  { value, isSecure }  → encrypt + send via CoAP');
  console.log('  GET  /paillier-key                         → utility Paillier public key');
  console.log('  GET  /status                               → health check');
  console.log('======================================================');
});
