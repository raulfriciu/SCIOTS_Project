import { coapGet, coapPost } from './coap_client_wrapper.js';
import { modPow, modInv, gcd } from 'bigint-crypto-utils';

async function run() {
  console.log('=== RSA BLIND SIGNATURE CLIENT STARTING ===');

  // Parse command line arguments
  const isSecure = process.argv.includes('--secure') || process.argv.includes('--coaps');
  
  // Configure proxy address, ports, and PSK credentials
  const host = '127.0.0.1';
  const port = isSecure ? 5684 : 5683; // 5684 for secure DTLS, 5683 for plain CoAP
  const protocol = isSecure ? 'coaps' : 'coap';
  
  const user = 'clientE';
  const key = '9yPztDNbbBkV41JIhL833lfXX+zyBfPaD8VLCK0C88w=';

  console.log(`Configured Mode: ${protocol.toUpperCase()}`);
  console.log(`Target URL: ${protocol}://${host}:${port}`);
  if (isSecure) {
    console.log(`PSK Identity: ${user}`);
  }
  console.log('-------------------------------------------');

  try {
    // Step 1: Fetch the RSA Public Key from the Decryption/Signature Server (via CoAP Proxy)
    console.log('Step 1: Fetching RSA Public Key from Server...');
    const keyUrl = `${protocol}://${host}:${port}/rsa/key`;
    const pubKeyData = await coapGet(keyUrl, isSecure, user, key);
    
    const n = BigInt(pubKeyData.n);
    const e = BigInt(pubKeyData.e);
    console.log(`  Successfully fetched RSA Public Key:`);
    console.log(`  n = ${n.toString().substring(0, 40)}...`);
    console.log(`  e = ${e.toString()}`);

    // Step 2: Prepare message to sign and blinding factor
    const message = 67890n; // Message to sign (as a BigInt)
    console.log(`\nStep 2: Preparing message to be signed blindly: m = ${message}`);
    
    // Select blinding factor r coprime to n
    let r = 777n; 
    while (gcd(r, n) !== 1n) {
      r += 1n;
    }
    console.log(`  Blinding factor chosen: r = ${r}`);

    // Step 3: Blind the message: m' = m * r^e mod n
    const re = modPow(r, e, n);
    const mBlind = (message * re) % n;
    console.log(`  Blinding message...`);
    console.log(`  Blinded message: m' = ${mBlind.toString().substring(0, 40)}...`);

    // Step 4: Send the blinded message to the Server for signing (via CoAP Proxy)
    console.log(`\nStep 4: Submitting blinded message to Server for signing...`);
    const signUrl = `${protocol}://${host}:${port}/rsa/sign`;
    const signResponse = await coapPost(signUrl, { blindedMessage: mBlind.toString() }, isSecure, user, key);
    
    const sBlind = BigInt(signResponse.signature);
    console.log(`  Received blinded signature from Server:`);
    console.log(`  s' = ${sBlind.toString().substring(0, 40)}...`);

    // Step 5: Unblind the signature: s = s' * r^-1 mod n
    console.log(`\nStep 5: Unblinding the signature...`);
    const rInv = modInv(r, n);
    const s = (sBlind * rInv) % n;
    console.log(`  Unblinded signature: s = ${s.toString().substring(0, 40)}...`);

    // Step 6: Verify the signature locally: s^e mod n == m
    console.log(`\nStep 6: Verifying signature locally...`);
    const verifiedMsg = modPow(s, e, n);
    console.log(`  Verification result (s^e mod n): ${verifiedMsg}`);

    if (verifiedMsg === message) {
      console.log('\n✅ RSA BLIND SIGNATURE SUCCESS!');
      console.log('   The signature is VALID and verified successfully!');
    } else {
      console.error('\n❌ RSA BLIND SIGNATURE FAILURE!');
      console.error('   The decrypted message does not match the original!');
    }

  } catch (err) {
    console.error('\n❌ ERROR during execution:', err.message);
  }
  console.log('===========================================');
}

run();
