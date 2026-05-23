import { modPow, primeSync, bitLength, gcd, modInv } from 'bigint-crypto-utils';
import crypto from 'crypto';

// Helper for LCM (Least Common Multiple)
function lcm(a, b) {
  return (a * b) / gcd(a, b);
}

// Function L(x) = (x - 1) / n
function L(x, n) {
  return (x - 1n) / n;
}

export class PaillierPublicKey {
  constructor(n, g) {
    this.n = BigInt(n);
    this.g = BigInt(g);
    this.n2 = this.n * this.n;
  }

  // Encrypts a message m (BigInt) with a random r
  encrypt(m) {
    const msg = BigInt(m);
    if (msg < 0n || msg >= this.n) {
      throw new Error('Message must be between 0 and n - 1');
    }

    // Generate random r in [1, n-1] coprime to n
    let r;
    do {
      // Create a random BigInt of similar bit length to n
      const bytes = Math.floor(Number(bitLength(this.n)) / 8);
      const randomBuffer = new Uint8Array(bytes);
      
      if (typeof globalThis.crypto?.getRandomValues === 'function') {
        globalThis.crypto.getRandomValues(randomBuffer);
      } else if (typeof crypto.webcrypto?.getRandomValues === 'function') {
        crypto.webcrypto.getRandomValues(randomBuffer);
      } else {
        const buf = crypto.randomBytes(bytes);
        randomBuffer.set(buf);
      }
      
      let hex = '0x';
      for (const byte of randomBuffer) {
        hex += byte.toString(16).padStart(2, '0');
      }
      r = BigInt(hex) % this.n;
    } while (r <= 0n || gcd(r, this.n) !== 1n);

    // c = (g^m * r^n) mod n^2
    // Since g = n + 1, g^m mod n^2 = (1 + m*n) mod n^2
    const gm = (1n + msg * this.n) % this.n2;
    const rn = modPow(r, this.n, this.n2);
    const c = (gm * rn) % this.n2;

    return c;
  }

  // Multiply two ciphertexts to get the homomorphic sum: c1 * c2 mod n^2
  add(c1, c2) {
    return (BigInt(c1) * BigInt(c2)) % this.n2;
  }
}

export class PaillierPrivateKey {
  constructor(lambda, mu, publicKey) {
    this.lambda = BigInt(lambda);
    this.mu = BigInt(mu);
    this.publicKey = publicKey;
  }

  // Decrypts a ciphertext c (BigInt)
  decrypt(c) {
    const cipher = BigInt(c);
    const n = this.publicKey.n;
    const n2 = this.publicKey.n2;

    // u = c^lambda mod n^2
    const u = modPow(cipher, this.lambda, n2);
    // m = L(u) * mu mod n
    const m = (L(u, n) * this.mu) % n;
    return m;
  }
}

// Generates Paillier Keypair
export function generatePaillierKeyPair(bitlength = 1024) {
  let p, q, n, lambda, g, mu;

  do {
    // Generate two large primes p and q
    p = primeSync(Math.floor(bitlength / 2) + 1);
    q = primeSync(Math.floor(bitlength / 2));
    n = p * q;
    lambda = lcm(p - 1n, q - 1n);
    g = n + 1n; // Efficient standard choice for g
    
    // Check if L(g^lambda mod n^2) is invertible modulo n
    try {
      const u = modPow(g, lambda, n * n);
      const lVal = L(u, n);
      mu = modInv(lVal, n);
    } catch (e) {
      mu = null;
    }
  } while (q === p || !mu || gcd(n, lambda) !== 1n);

  const publicKey = new PaillierPublicKey(n, g);
  const privateKey = new PaillierPrivateKey(lambda, mu, publicKey);

  return { publicKey, privateKey };
}
