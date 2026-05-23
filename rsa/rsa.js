import { modPow, primeSync, bitLength, gcd, modInv } from 'bigint-crypto-utils'

export class RsaPublicKey{
    constructor (n, e){
        this.n = n;
        this.e = e;
    }
    
    encrypt(m) {
        return modPow(m, this.e, this.n); 
    }

    verify(s) {
        return modPow(s, this.e, this.n);
    }

    blind(m, r) {
        const re = modPow(BigInt(r), this.e, this.n);
        return (BigInt(m) * re) % this.n;
    }

    unblind(s_blinded, r) {
        const rInv = modInv(BigInt(r), this.n);
        return (BigInt(s_blinded) * rInv) % this.n;
    }
}

export class RsaPrivateKey{
    constructor (n, d){
        this.n = n;
        this.d = d;
    }
    
    decrypt(c) {
        return modPow(c, this.d, this.n); 
    }

    sign(m) {
        return modPow(m, this.d, this.n);
    }
}

export function generateKeyPair(bitlength) {
  let p, q, n, phi, e;

  do {
    p = primeSync(Math.floor(bitlength / 2) + 1);
    q = primeSync(Math.floor(bitlength / 2));
    phi = (p - 1n) * (q - 1n);
    e = 65537n; // Common choice for e
    n = p * q;
  } while (q === p || bitLength(n) != bitlength || gcd(e, phi) !== 1n)

  const d = modInv(e, phi); 

  return {
    publicKey: new RsaPublicKey(n, e),
    privateKey: new RsaPrivateKey(n, d)
  };
}