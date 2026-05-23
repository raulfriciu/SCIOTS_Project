import { coapGet, coapPost } from './coap_client_wrapper.js';
import { PaillierPublicKey } from '../rsa/paillier.js';

async function run() {
  console.log('=== PAILLIER HOMOMORPHIC ENCRYPTION CLIENT STARTING ===');

  // Parse command line arguments
  const isSecure = process.argv.includes('--secure') || process.argv.includes('--coaps');
  
  // Configure proxy hosts, ports, and PSK credentials
  const host = '127.0.0.1';
  const protocol = isSecure ? 'coaps' : 'coap';
  
  // Port for Decryption Server (serverE)
  const decryptorPort = isSecure ? 5684 : 5683;
  // Port for Aggregator Server
  const aggregatorPort = isSecure ? 5686 : 5685;

  const user = 'clientA';
  const key = 'EiAT3eboMqOa0ddtwsiX57JUBnw08ClON7wLR7n8N2M=';

  console.log(`Configured Mode: ${protocol.toUpperCase()}`);
  console.log(`Decryptor URL: ${protocol}://${host}:${decryptorPort}`);
  console.log(`Aggregator URL: ${protocol}://${host}:${aggregatorPort}`);
  if (isSecure) {
    console.log(`PSK Identity: ${user}`);
  }
  console.log('----------------------------------------------------');

  try {
    // Step 1: Fetch the Paillier Public Key from the Decryption Server (via CoAP Proxy)
    console.log('Step 1: Fetching Paillier Public Key from Decryption Server...');
    const keyUrl = `${protocol}://${host}:${decryptorPort}/paillier/key`;
    const pubKeyData = await coapGet(keyUrl, isSecure, user, key);
    
    const n = BigInt(pubKeyData.n);
    const g = BigInt(pubKeyData.g);
    console.log(`  Successfully fetched Paillier Public Key:`);
    console.log(`  n = ${n.toString().substring(0, 40)}...`);
    console.log(`  g = ${g.toString().substring(0, 40)}...`);

    // Instantiate the Paillier Public Key locally for encryption
    const publicKey = new PaillierPublicKey(n, g);

    // Step 2: Encrypt two values locally
    const v1 = 15n;
    const v2 = 27n;
    console.log(`\nStep 2: Encrypting values locally: v1 = ${v1}, v2 = ${v2}`);
    
    const c1 = publicKey.encrypt(v1);
    const c2 = publicKey.encrypt(v2);
    console.log(`  Encrypted v1 to c1: ${c1.toString().substring(0, 40)}...`);
    console.log(`  Encrypted v2 to c2: ${c2.toString().substring(0, 40)}...`);

    // Step 3: Send encrypted data to the Aggregator (via CoAP Proxy)
    console.log(`\nStep 3: Submitting ciphertexts to Aggregator...`);
    const submitUrl = `${protocol}://${host}:${aggregatorPort}/paillier/submit`;
    
    console.log(`  Submitting c1...`);
    const res1 = await coapPost(submitUrl, { ciphertext: c1.toString() }, isSecure, user, key);
    console.log(`  Response: ${res1.message} (Buffer size: ${res1.bufferSize})`);

    console.log(`  Submitting c2...`);
    const res2 = await coapPost(submitUrl, { ciphertext: c2.toString() }, isSecure, user, key);
    console.log(`  Response: ${res2.message} (Buffer size: ${res2.bufferSize})`);

    // Step 4: Ask the Aggregator to aggregate and call Decryptor
    console.log(`\nStep 4: Requesting Aggregator to perform homomorphic sum...`);
    const aggUrl = `${protocol}://${host}:${aggregatorPort}/paillier/aggregate`;
    const aggRes = await coapPost(aggUrl, {}, isSecure, user, key);

    console.log(`  Aggregator combined ciphertext c_sum = c1 * c2 mod n^2`);
    console.log(`  Aggregator received plaintext sum from Decryptor: ${aggRes.decryptedSum}`);

    // Step 5: Verify the result
    const expectedSum = v1 + v2;
    console.log(`\nStep 5: Verifying result locally...`);
    console.log(`  Expected Sum: ${v1} + ${v2} = ${expectedSum}`);
    console.log(`  Aggregated Decrypted Sum: ${aggRes.decryptedSum}`);

    if (BigInt(aggRes.decryptedSum) === expectedSum) {
      console.log('\n✅ PAILLIER HOMOMORPHIC ENCRYPTION SUCCESS!');
      console.log('   The aggregator successfully summed encrypted values without decrypting them!');
    } else {
      console.error('\n❌ PAILLIER HOMOMORPHIC ENCRYPTION FAILURE!');
      console.error('   The decrypted sum does not match the mathematical expectation!');
    }

  } catch (err) {
    console.error('\n❌ ERROR during execution:', err.message);
  }
  console.log('====================================================');
}

run();
