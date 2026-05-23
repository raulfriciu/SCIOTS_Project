import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import net from 'net';
import { exec, execSync } from 'child_process';
import os from 'os';
import { coapGet, coapPost } from '../client/coap_client_wrapper.js';
import { PaillierPublicKey } from '../rsa/paillier.js';
import { gcd, modPow, modInv } from 'bigint-crypto-utils';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
app.use(express.json());

// Serve static dashboard files
app.use(express.static(__dirname));

const PORT = 5000;

// In-memory system logs
let systemLogs = [];

function logEvent(source, type, message, details = null) {
  const timestamp = new Date().toLocaleTimeString();
  const event = { timestamp, source, type, message, details };
  systemLogs.push(event);
  if (systemLogs.length > 100) {
    systemLogs.shift();
  }
  console.log(`[${source}] [${type}] ${message}`);
}

// Detect Windows Host IP if running inside WSL
let windowsHostIp = null;
try {
  if (process.platform === 'linux' && os.release().toLowerCase().includes('microsoft')) {
    const route = execSync("ip route | grep default | awk '{print $3}'", { encoding: 'utf8' }).trim();
    if (route) {
      windowsHostIp = route;
      console.log(`[WSL Network] Windows Host IP detected: ${windowsHostIp}`);
    }
  }
} catch (e) {
  // Ignore
}

// Helper to determine the active host for a given port (127.0.0.1 or WSL host IP)
function getActiveHostForPort(port) {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    socket.setTimeout(150);
    socket.on('connect', () => {
      socket.destroy();
      resolve('127.0.0.1');
    });
    socket.on('timeout', () => {
      socket.destroy();
      if (windowsHostIp) {
        resolve(windowsHostIp);
      } else {
        resolve('127.0.0.1');
      }
    });
    socket.on('error', () => {
      if (windowsHostIp) {
        // Try Windows Host IP instead
        const socketHost = new net.Socket();
        socketHost.setTimeout(150);
        socketHost.on('connect', () => {
          socketHost.destroy();
          resolve(windowsHostIp);
        });
        socketHost.on('error', () => {
          resolve('127.0.0.1');
        });
        socketHost.on('timeout', () => {
          socketHost.destroy();
          resolve('127.0.0.1');
        });
        socketHost.connect(port, windowsHostIp);
      } else {
        resolve('127.0.0.1');
      }
    });
    socket.connect(port, '127.0.0.1');
  });
}

// Helper to check if a TCP port is open locally in WSL/localhost or on the Windows Host
function checkTcpPort(port) {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    socket.setTimeout(200);
    socket.on('connect', () => {
      socket.destroy();
      resolve(true);
    });
    socket.on('timeout', () => {
      socket.destroy();
      if (windowsHostIp) {
        // Try the Windows host
        const socketHost = new net.Socket();
        socketHost.setTimeout(200);
        socketHost.on('connect', () => {
          socketHost.destroy();
          resolve(true);
        });
        socketHost.on('error', () => resolve(false));
        socketHost.on('timeout', () => { socketHost.destroy(); resolve(false); });
        socketHost.connect(port, windowsHostIp);
      } else {
        resolve(false);
      }
    });
    socket.on('error', () => {
      if (windowsHostIp) {
        // Try the Windows host
        const socketHost = new net.Socket();
        socketHost.setTimeout(200);
        socketHost.on('connect', () => {
          socketHost.destroy();
          resolve(true);
        });
        socketHost.on('error', () => resolve(false));
        socketHost.on('timeout', () => { socketHost.destroy(); resolve(false); });
        socketHost.connect(port, windowsHostIp);
      } else {
        resolve(false);
      }
    });
    socket.connect(port, '127.0.0.1');
  });
}

// Helper to check if proxy processes are active in WSL
function checkProxyProcess() {
  return new Promise((resolve) => {
    const isWindows = process.platform === 'win32';
    const prefix = isWindows ? 'wsl ' : '';
    // Run pgrep or ps to see if the proxy is running
    exec(`${prefix}pgrep -f coap-http-reverseproxy`, (error, stdout) => {
      if (error || !stdout.trim()) {
        resolve(false);
      } else {
        resolve(true);
      }
    });
  });
}

// Endpoint: Check system statuses
app.get('/api/status', async (req, res) => {
  const isServerEActive = await checkTcpPort(3000);
  const isAggregatorActive = await checkTcpPort(4000);
  const isProxyActive = await checkProxyProcess();

  res.json({
    serverE: isServerEActive,
    aggregator: isAggregatorActive,
    proxy: isProxyActive
  });
});

// Endpoint: Get Aggregator RSA Public Key
app.get('/api/aggregator/key', async (req, res) => {
  try {
    const host = await getActiveHostForPort(4000);
    const response = await fetch(`http://${host}:4000/rsa/key`);
    const data = await response.json();
    res.json(data);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Endpoint: Get Paillier Public Key directly from serverE (no aggregation side effect)
app.get('/api/paillier-key', async (req, res) => {
  const { isSecure } = req.query;
  const secure = isSecure === 'true';
  const port = secure ? 5684 : 5683;
  const protocol = secure ? 'coaps' : 'coap';
  const user = 'clientA';
  const key = 'EiAT3eboMqOa0ddtwsiX57JUBnw08ClON7wLR7n8N2M=';
  try {
    const keyUrl = `${protocol}://127.0.0.1:${port}/paillier/key`;
    const pubKeyData = await coapGet(keyUrl, secure, user, key);
    if (!pubKeyData || !pubKeyData.n) {
      return res.status(503).json({ error: 'serverE no responde' });
    }
    res.json(pubKeyData);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Endpoint: Get RSA Public Key directly from serverE (no side effect)
app.get('/api/rsa-key', async (req, res) => {
  const { isSecure } = req.query;
  const secure = isSecure === 'true';
  const port = secure ? 5684 : 5683;
  const protocol = secure ? 'coaps' : 'coap';
  const user = 'clientE';
  const key = '9yPztDNbbBkV41JIhL833lfXX+zyBfPaD8VLCK0C88w=';
  try {
    const keyUrl = `${protocol}://127.0.0.1:${port}/rsa/key`;
    const pubKeyData = await coapGet(keyUrl, secure, user, key);
    if (!pubKeyData || !pubKeyData.n) {
      return res.status(503).json({ error: 'serverE no responde' });
    }
    res.json(pubKeyData);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Endpoint: Get System Logs
app.get('/api/logs', (req, res) => {
  res.json(systemLogs);
});

// Endpoint: Clear Logs
app.post('/api/logs/clear', (req, res) => {
  systemLogs = [];
  res.json({ success: true });
});

// Endpoint: Send Paillier Encrypted Value from a Meter
app.post('/api/send-paillier', async (req, res) => {
  const { meterId, value, isSecure } = req.body;
  const numValue = BigInt(value);
  
  const host = '127.0.0.1';
  const decryptorPort = isSecure ? 5684 : 5683;
  const aggregatorPort = isSecure ? 5686 : 5685;
  const protocol = isSecure ? 'coaps' : 'coap';
  
  const user = 'clientA';
  const key = 'EiAT3eboMqOa0ddtwsiX57JUBnw08ClON7wLR7n8N2M=';

  logEvent(`Meter ${meterId}`, 'START', `Starting Paillier Homomorphic Flow for consumption: ${value} kWh`);

  try {
    // Step 1: Fetch the Paillier Public Key from Decryption Server
    const keyUrl = `${protocol}://${host}:${decryptorPort}/paillier/key`;
    logEvent(`Meter ${meterId}`, 'COAP_REQ', `[GET] Fetching Paillier Public Key from Decryption Server via Proxy...`, { url: keyUrl });
    
    const pubKeyData = await coapGet(keyUrl, isSecure, user, key);
    if (!pubKeyData || !pubKeyData.n || !pubKeyData.g) {
      throw new Error("No se pudo obtener la clave pública Paillier de serverE. Comprueba que el servidor y los proxies estén corriendo.");
    }
    const n = BigInt(pubKeyData.n);
    const g = BigInt(pubKeyData.g);
    
    logEvent(`Meter ${meterId}`, 'COAP_RES', `Successfully fetched Paillier Public Key`, {
      n: n.toString(),
      g: g.toString()
    });

    // Step 2: Encrypt the value locally
    logEvent(`Meter ${meterId}`, 'CRYPT', `Encrypting value locally: v = ${value}`);
    const publicKey = new PaillierPublicKey(n, g);
    const ciphertext = publicKey.encrypt(numValue);
    
    logEvent(`Meter ${meterId}`, 'CRYPT', `Generated ciphertext: c = ${ciphertext.toString().substring(0, 30)}...`);

    // Step 3: Send encrypted data to the Aggregator
    const submitUrl = `${protocol}://${host}:${aggregatorPort}/paillier/submit`;
    logEvent(`Meter ${meterId}`, 'COAP_REQ', `[POST] Submitting ciphertext to Aggregator via Proxy...`, {
      url: submitUrl,
      ciphertext: ciphertext.toString()
    });

    const submitResponse = await coapPost(submitUrl, { ciphertext: ciphertext.toString() }, isSecure, user, key);
    
    logEvent(`Meter ${meterId}`, 'COAP_RES', `Aggregator Response: ${submitResponse.message} (Buffer size: ${submitResponse.bufferSize})`);

    res.json({
      success: true,
      step: 'SUBMITTED',
      details: {
        n: n.toString(),
        g: g.toString(),
        value: value.toString(),
        ciphertext: ciphertext.toString(),
        bufferSize: submitResponse.bufferSize
      }
    });

  } catch (err) {
    logEvent(`Meter ${meterId}`, 'ERROR', `Error during Paillier flow: ${err.message}`);
    res.status(500).json({ success: false, error: err.message });
  }
});

// Endpoint: Send RSA Blind Signature Request from a Meter
app.post('/api/send-rsa', async (req, res) => {
  const { meterId, value, isSecure } = req.body;
  const message = BigInt(value);
  
  const host = '127.0.0.1';
  const decryptorPort = isSecure ? 5684 : 5683;
  const protocol = isSecure ? 'coaps' : 'coap';
  
  const user = 'clientE';
  const key = '9yPztDNbbBkV41JIhL833lfXX+zyBfPaD8VLCK0C88w=';

  logEvent(`Meter ${meterId}`, 'START', `Starting RSA Blind Signature Flow for message: ${value}`);

  try {
    // Step 1: Fetch the RSA Public Key from the Decryption/Signature Server
    const keyUrl = `${protocol}://${host}:${decryptorPort}/rsa/key`;
    logEvent(`Meter ${meterId}`, 'COAP_REQ', `[GET] Fetching RSA Public Key from Decryption Server via Proxy...`, { url: keyUrl });
    
    const pubKeyData = await coapGet(keyUrl, isSecure, user, key);
    if (!pubKeyData || !pubKeyData.n || !pubKeyData.e) {
      throw new Error("No se pudo obtener la clave pública RSA de serverE. Comprueba que el servidor y los proxies estén corriendo.");
    }
    const n = BigInt(pubKeyData.n);
    const e = BigInt(pubKeyData.e);
    
    logEvent(`Meter ${meterId}`, 'COAP_RES', `Successfully fetched RSA Public Key`, {
      n: n.toString(),
      e: e.toString()
    });

    // Step 2: Select blinding factor r coprime to n and blind the message
    logEvent(`Meter ${meterId}`, 'CRYPT', `Selecting blinding factor r coprime to n...`);
    let r = 777n; 
    while (gcd(r, n) !== 1n) {
      r += 1n;
    }
    
    logEvent(`Meter ${meterId}`, 'CRYPT', `Blinding factor chosen: r = ${r}`);
    
    const re = modPow(r, e, n);
    const mBlind = (message * re) % n;
    
    logEvent(`Meter ${meterId}`, 'CRYPT', `Blinded message calculated: m' = (m * r^e) mod n = ${mBlind.toString().substring(0, 30)}...`);

    // Step 3: Send the blinded message to the Server for signing
    const signUrl = `${protocol}://${host}:${decryptorPort}/rsa/sign`;
    logEvent(`Meter ${meterId}`, 'COAP_REQ', `[POST] Submitting blinded message to Signature Server via Proxy...`, {
      url: signUrl,
      blindedMessage: mBlind.toString()
    });

    const signResponse = await coapPost(signUrl, { blindedMessage: mBlind.toString() }, isSecure, user, key);
    if (!signResponse || !signResponse.signature) {
      throw new Error("No se pudo obtener la firma ciega de serverE. Comprueba que el servidor y los proxies estén corriendo.");
    }
    const sBlind = BigInt(signResponse.signature);
    
    logEvent(`Meter ${meterId}`, 'COAP_RES', `Received blinded signature: s' = ${sBlind.toString().substring(0, 30)}...`);

    // Step 4: Unblind the signature
    logEvent(`Meter ${meterId}`, 'CRYPT', `Unblinding signature: s = s' * r^-1 mod n...`);
    const rInv = modInv(r, n);
    const s = (sBlind * rInv) % n;
    
    logEvent(`Meter ${meterId}`, 'CRYPT', `Unblinded signature generated: s = ${s.toString().substring(0, 30)}...`);

    // Step 5: Verify the signature locally
    logEvent(`Meter ${meterId}`, 'CRYPT', `Verifying signature locally: s^e mod n == m...`);
    const verifiedMsg = modPow(s, e, n);
    const isSuccess = verifiedMsg === message;
    
    logEvent(`Meter ${meterId}`, 'CRYPT', `Verification Result: ${isSuccess ? 'SUCCESS ✅' : 'FAILED ❌'} (s^e mod n = ${verifiedMsg})`);

    res.json({
      success: true,
      isSuccess,
      details: {
        n: n.toString(),
        e: e.toString(),
        message: message.toString(),
        r: r.toString(),
        mBlind: mBlind.toString(),
        sBlind: sBlind.toString(),
        s: s.toString(),
        verifiedMsg: verifiedMsg.toString()
      }
    });

  } catch (err) {
    logEvent(`Meter ${meterId}`, 'ERROR', `Error during RSA blind signature flow: ${err.message}`);
    res.status(500).json({ success: false, error: err.message });
  }
});

// Endpoint: Perform Homomorphic Aggregation on the Aggregator (Only package/multiply!)
app.post('/api/aggregate', async (req, res) => {
  const { isSecure } = req.body;
  const host = '127.0.0.1';
  const aggregatorPort = isSecure ? 5686 : 5685;
  const protocol = isSecure ? 'coaps' : 'coap';
  
  const user = 'clientA';
  const key = 'EiAT3eboMqOa0ddtwsiX57JUBnw08ClON7wLR7n8N2M=';

  logEvent('Aggregator', 'START', 'Starting Homomorphic Aggregation (Packaging)...');

  try {
    const aggUrl = `${protocol}://${host}:${aggregatorPort}/paillier/aggregate`;
    logEvent('Aggregator', 'COAP_REQ', `[POST] Triggering aggregation via Proxy...`, { url: aggUrl });
    
    const aggRes = await coapPost(aggUrl, {}, isSecure, user, key);
    
    logEvent('Aggregator', 'COAP_RES', `Homomorphic Packaging Successful! Ciphertexts multiplied modulo n².`, {
      aggregatedCount: aggRes.aggregatedCount,
      ciphertextSum: aggRes.ciphertextSum
    });

    res.json({
      success: true,
      details: {
        aggregatedCount: aggRes.aggregatedCount,
        ciphertextSum: aggRes.ciphertextSum
      }
    });

  } catch (err) {
    logEvent('Aggregator', 'ERROR', `Error during aggregation: ${err.message}`);
    res.status(500).json({ success: false, error: err.message });
  }
});

// Endpoint: Sign and Send Aggregated Ciphertext to Central Server
app.post('/api/sign-and-send', async (req, res) => {
  const { isSecure } = req.body;
  const host = '127.0.0.1';
  const aggregatorPort = isSecure ? 5686 : 5685;
  const protocol = isSecure ? 'coaps' : 'coap';
  
  const user = 'clientA';
  const key = 'EiAT3eboMqOa0ddtwsiX57JUBnw08ClON7wLR7n8N2M=';

  logEvent('Aggregator', 'START', 'Aggregator signing homomorphic sum & sending to Central...');

  try {
    const signSendUrl = `${protocol}://${host}:${aggregatorPort}/paillier/sign-and-send`;
    logEvent('Aggregator', 'COAP_REQ', `[POST] Requesting Aggregator to sign and submit...`, { url: signSendUrl });
    
    const result = await coapPost(signSendUrl, {}, isSecure, user, key);
    
    logEvent('Central', 'RECEIVE', `📥 Stored signed ciphertext in Vault! Waiting signature verification...`, {
      ciphertextSum: result.ciphertextSum,
      signature: result.signature
    });

    res.json({
      success: true,
      details: {
        ciphertextSum: result.ciphertextSum,
        signature: result.signature
      }
    });

  } catch (err) {
    logEvent('Aggregator', 'ERROR', `Error during sign-and-send flow: ${err.message}`);
    res.status(500).json({ success: false, error: err.message });
  }
});

// Endpoint: Verify Aggregator RSA signature on Central (serverE)
app.post('/api/verify-signature', async (req, res) => {
  logEvent('Central', 'START', 'Verifying Aggregator RSA Signature...');
  try {
    const host = await getActiveHostForPort(3000);
    const response = await fetch(`http://${host}:3000/paillier/verify-signature`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' }
    });
    const data = await response.json();
    if (response.ok && data.verified) {
      logEvent('Central', 'VERIFY', '✅ Aggregator RSA Signature verified successfully! Ready for decryption.');
      res.json({ success: true, verified: true });
    } else {
      logEvent('Central', 'ERROR', `❌ Signature verification failed: ${data.error}`);
      res.status(401).json({ success: false, error: data.error });
    }
  } catch (e) {
    logEvent('Central', 'ERROR', `Error contacting Decryption Server: ${e.message}`);
    res.status(500).json({ success: false, error: e.message });
  }
});

// Endpoint: Decrypt consolidates sum on Central (serverE)
app.post('/api/decrypt', async (req, res) => {
  logEvent('Central', 'START', 'Decrypting consolidated sum using Paillier Private Key...');
  try {
    const host = await getActiveHostForPort(3000);
    const response = await fetch(`http://${host}:3000/paillier/decrypt`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' }
    });
    const data = await response.json();
    if (response.ok && data.decrypted) {
      logEvent('Central', 'DECRYPT', `🔓 Decryption successful! Consolidated sum: ${data.decrypted} kWh`);
      res.json({ success: true, decrypted: data.decrypted });
    } else {
      logEvent('Central', 'ERROR', `❌ Decryption failed: ${data.error}`);
      res.status(400).json({ success: false, error: data.error });
    }
  } catch (e) {
    logEvent('Central', 'ERROR', `Error contacting Decryption Server: ${e.message}`);
    res.status(500).json({ success: false, error: e.message });
  }
});

// Endpoint: Reset Aggregator Buffer
app.post('/api/reset-buffer', async (req, res) => {
  const { isSecure } = req.body;
  const host = '127.0.0.1';
  const aggregatorPort = isSecure ? 5686 : 5685;
  const protocol = isSecure ? 'coaps' : 'coap';
  
  const user = 'clientA';
  const key = 'EiAT3eboMqOa0ddtwsiX57JUBnw08ClON7wLR7n8N2M=';

  logEvent('Aggregator', 'RESET', 'Requesting aggregator buffer reset...');

  try {
    const resetUrl = `${protocol}://${host}:${aggregatorPort}/paillier/reset`;
    const response = await coapPost(resetUrl, {}, isSecure, user, key);
    logEvent('Aggregator', 'RESET', `Buffer cleared: ${response.message}`);
    res.json({ success: true, message: response.message });
  } catch (err) {
    logEvent('Aggregator', 'ERROR', `Error resetting buffer: ${err.message}`);
    res.status(500).json({ success: false, error: err.message });
  }
});

// Start the Dashboard Bridge Server
app.listen(PORT, () => {
  console.log(`======================================================`);
  console.log(`SCIOTS Interactive Web Dashboard Server is running!`);
  console.log(`Open in your browser: http://localhost:${PORT}`);
  console.log(`======================================================`);
});
