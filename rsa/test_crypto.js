import { generateKeyPair, RsaPublicKey, RsaPrivateKey } from './rsa.js';
import { generatePaillierKeyPair, PaillierPublicKey, PaillierPrivateKey } from './paillier.js';
import { modInv, gcd } from 'bigint-crypto-utils';

console.log('=== STARTING CRYPTO MATHEMATICS TESTS ===\n');

// 1. Paillier Homomorphic Test
try {
  console.log('--- Paillier Homomorphic Test ---');
  const { publicKey, privateKey } = generatePaillierKeyPair(512); // Use 512-bit for fast testing
  console.log('Keys generated successfully.');
  console.log('Public Key n:', publicKey.n.toString().substring(0, 30) + '...');
  
  const m1 = 42n;
  const m2 = 100n;
  console.log(`Original plaintexts: m1 = ${m1}, m2 = ${m2}`);
  
  const c1 = publicKey.encrypt(m1);
  const c2 = publicKey.encrypt(m2);
  console.log('Ciphertexts encrypted.');
  
  // Aggregator multiplies ciphertexts: c_sum = c1 * c2 mod n^2
  const cSum = publicKey.add(c1, c2);
  console.log('Ciphertexts aggregated (multiplied).');
  
  // Decryptor decrypts sum
  const decryptedSum = privateKey.decrypt(cSum);
  console.log(`Decrypted sum: ${decryptedSum}`);
  
  if (decryptedSum === m1 + m2) {
    console.log('✅ SUCCESS: Paillier homomorphic addition works perfectly!\n');
  } else {
    console.error('❌ FAILURE: Paillier decryption did not match the sum.\n');
  }
} catch (e) {
  console.error('❌ ERROR in Paillier test:', e);
}

// 2. RSA Blind Signature Test
try {
  console.log('--- RSA Blind Signature Test ---');
  const { publicKey, privateKey } = generateKeyPair(1024);
  console.log('Keys generated successfully.');
  
  const m = 12345n; // The message we want to sign blindly
  console.log(`Original message to be signed blindly: m = ${m}`);
  
  // Choose random blinding factor r, coprime to n
  let r;
  do {
    r = 1357n; // A constant or random coprime
  } while (gcd(r, publicKey.n) !== 1n);
  
  // Blinding
  const mBlind = publicKey.blind(m, r);
  console.log(`Blinded message: m' = ${mBlind.toString().substring(0, 30)}...`);
  
  // Signer signs blinded message
  const sBlind = privateKey.sign(mBlind);
  console.log(`Blinded signature s': ${sBlind.toString().substring(0, 30)}...`);
  
  // Client unblinds signature
  const s = publicKey.unblind(sBlind, r);
  console.log(`Unblinded signature s: ${s.toString().substring(0, 30)}...`);
  
  // Verification
  const verified = publicKey.verify(s);
  console.log(`Verified message (s^e mod n): ${verified}`);
  
  if (verified === m) {
    console.log('✅ SUCCESS: RSA Blind signature works perfectly!\n');
  } else {
    console.error('❌ FAILURE: RSA signature verification failed.\n');
  }
} catch (e) {
  console.error('❌ ERROR in RSA test:', e);
}
