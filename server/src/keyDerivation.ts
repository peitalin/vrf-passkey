import { decode } from 'cbor-x';
import { createHash } from 'crypto';
import { KeyPairEd25519, PublicKey, KeyType } from '@near-js/crypto';
import bs58 from 'bs58';

/**
 * Derives a NEAR public key string from a COSE credential public key.
 *
 * @param credentialPublicKey The COSE public key (typically from a WebAuthn attestation object).
 * @returns The derived NEAR public key string (e.g., "ed25519:...") or null if derivation fails or key type is unsupported.
 */
export const deriveNearPublicKeyFromCOSE = (credentialPublicKey: Buffer): string => {
  console.log('Raw credentialPublicKey (COSE key) for derivation:', credentialPublicKey);
  let nearPublicKeyToStore: string = "";

  try {
    const coseKeyObject = decode(credentialPublicKey);
    console.log('Decoded COSE Key Object:', coseKeyObject);

    const kty = coseKeyObject[1]; // Key Type (label 1)
    const alg = coseKeyObject[3]; // Algorithm (label 3)

    console.log(`COSE Key Details: kty=${kty}, alg=${alg}`);

    if (kty === 1 && alg === -8) { // OKP (Octet Key Pair), EdDSA (Ed25519)
      const xCoord = coseKeyObject[-2]; // x-coordinate (label -2 for OKP)
      if (xCoord instanceof Uint8Array && xCoord.length === 32) {
        const nearEd25519Pk = new PublicKey({ keyType: KeyType.ED25519, data: Buffer.from(xCoord) });
        nearPublicKeyToStore = nearEd25519Pk.toString();
        console.log('Derived NEAR Ed25519 PK directly from COSE Ed25519 key:', nearPublicKeyToStore);
      } else {
        console.error('COSE Ed25519 key does not have a valid x-coordinate (expected Uint8Array of length 32).');
      }
    } else if (kty === 2 && alg === -7) { // EC2 (Elliptic Curve), ES256 (P-256)
      const crv = coseKeyObject[-1]; // Curve (label -1 for EC2)
      const x = coseKeyObject[-2];   // x-coordinate (label -2 for EC2)
      const y = coseKeyObject[-3];   // y-coordinate (label -3 for EC2)

      if (crv === 1 && x instanceof Uint8Array && y instanceof Uint8Array) { // crv 1 is P-256
        const hash = createHash('sha256');
        hash.update(Buffer.from(x));
        hash.update(Buffer.from(y));
        const seedBytes = hash.digest(); // This is a 32-byte Buffer

        const secretKeyBase58 = bs58.encode(seedBytes.subarray(0, 32));
        console.log("Derived secretKeyBase58 (seed for Ed25519): ", secretKeyBase58);
        const nearKeyPair = new KeyPairEd25519(secretKeyBase58);

        // For logging/debugging the full key if needed, though not strictly part of derivation to public key
        // const rawSeed = seedBytes.subarray(0, 32);
        // const rawPublicKeyData = nearKeyPair.getPublicKey().data;
        // const combinedKeyMaterial = Buffer.concat([rawSeed, Buffer.from(rawPublicKeyData)]);
        // const fullPrivateKeyString = `ed25519:${bs58.encode(combinedKeyMaterial)}`;
        // console.log("Constructed full Ed25519 private key (seed + pk):", fullPrivateKeyString);
        // console.log("Value from nearKeyPair.secretKey for comparison:", nearKeyPair.secretKey);

        nearPublicKeyToStore = nearKeyPair.getPublicKey().toString();
        console.log('Derived NEAR Ed25519 PK from P-256 COSE key:', nearPublicKeyToStore);
      } else {
        console.error('COSE P-256 key is missing curve, x, or y, or curve is not P-256, or x/y are not Uint8Arrays.');
      }
    } else {
      console.warn(`Unsupported COSE key type/algorithm: kty=${kty}, alg=${alg}. Cannot derive NEAR PK.`);
    }
  } catch (parseError: any) {
    console.error('Error parsing COSE key or deriving NEAR PK:', parseError);
    // Fall through to return null
  }

  if (nearPublicKeyToStore) {
    console.log('Successfully derived/extracted NEAR Public Key:', nearPublicKeyToStore);
  } else {
    console.error('Failed to derive or extract a NEAR Public Key from the COSE key (unsupported type or error).');
  }
  return nearPublicKeyToStore;
};