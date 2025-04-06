import { AES, enc, mode, pad } from "crypto-js";
import { x25519 } from "@noble/curves/ed25519";
import { sha512 } from "@noble/hashes/sha512";
import { randomBytes } from "@noble/hashes/utils";

const APP_INFO = "X3DH_Demo_v1";

export class CryptoUtils {
  /**
   * Generates a safety number from two identity keys.
   * The safety number is a hash of the lexicographically ordered identity keys,
   * which helps users verify they're communicating with the correct person.
   */
  static generateSafetyNumber(key1: string, key2: string): string {
    // Compare keys lexicographically to determine order
    const [firstKey, secondKey] = key1 < key2 ? [key1, key2] : [key2, key1];

    // Concatenate the keys in lexicographical order
    const combinedKeys = Buffer.concat([
      Buffer.from(firstKey, "base64"),
      Buffer.from(secondKey, "base64"),
    ]);

    // Generate SHA-512 hash of the combined keys
    const hash = sha512(combinedKeys);

    // Convert to base64 and take first 12 characters for display
    return Buffer.from(hash).toString("base64").slice(0, 12);
  }

  static generateKeyPair(): { publicKey: string; privateKey: string } {
    const privateKey = randomBytes(32);
    const publicKey = x25519.getPublicKey(privateKey);

    return {
      publicKey: Buffer.from(publicKey).toString("base64"),
      privateKey: Buffer.from(privateKey).toString("base64"),
    };
  }

  static generatePreKey(): { publicKey: string; privateKey: string } {
    return this.generateKeyPair();
  }

  static generateSignedPreKey(identityPrivateKey: string): {
    publicKey: string;
    privateKey: string;
    signature: string;
  } {
    const keyPair = this.generateKeyPair();
    const signature = this.sign(identityPrivateKey, keyPair.publicKey);
    return {
      publicKey: keyPair.publicKey,
      privateKey: keyPair.privateKey,
      signature,
    };
  }

  static sign(privateKey: string, data: string): string {
    const privateKeyBytes = Buffer.from(privateKey, "base64");
    const dataBytes = Buffer.from(data, "base64");
    const signatureInput = Buffer.concat([privateKeyBytes, dataBytes]);
    const signature = sha512(signatureInput);
    return Buffer.from(signature).toString("base64");
  }

  static encrypt(message: string, key: string): string {
    const derivedKey = this.deriveKey(key);
    return AES.encrypt(message, derivedKey, {
      mode: mode.CBC,
      padding: pad.Pkcs7,
    }).toString();
  }

  static decrypt(encryptedMessage: string, key: string): string {
    const derivedKey = this.deriveKey(key);
    const bytes = AES.decrypt(encryptedMessage, derivedKey, {
      mode: mode.CBC,
      padding: pad.Pkcs7,
    });
    return bytes.toString(enc.Utf8);
  }

  static deriveSharedSecret(privateKey: string, publicKey: string): string {
    const privateKeyBytes = Buffer.from(privateKey, "base64");
    const publicKeyBytes = Buffer.from(publicKey, "base64");
    const sharedSecret = x25519.getSharedSecret(
      privateKeyBytes,
      publicKeyBytes
    );
    return Buffer.from(sharedSecret).toString("base64");
  }

  private static deriveKey(keyMaterial: string): string {
    const keyBytes = Buffer.from(keyMaterial, "base64");
    const info = Buffer.from(APP_INFO);
    const derivationInput = Buffer.concat([keyBytes, info]);
    const derivedKey = sha512(derivationInput);
    return Buffer.from(derivedKey).slice(0, 32).toString("base64");
  }

  static combineSharedSecrets(secrets: string[]): string {
    const combinedSecrets = secrets.map((s) => Buffer.from(s, "base64"));
    const concatenated = Buffer.concat(combinedSecrets);
    const info = Buffer.from(APP_INFO);
    const finalInput = Buffer.concat([concatenated, info]);
    const finalHash = sha512(finalInput);
    return Buffer.from(finalHash).toString("base64");
  }
}
