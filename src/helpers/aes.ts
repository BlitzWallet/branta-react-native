import { sha256 } from "@noble/hashes/sha2.js";
import { hmac } from "@noble/hashes/hmac.js";
import { gcm } from "@noble/ciphers/aes.js";
import { randomBytes, utf8ToBytes, concatBytes } from "@noble/hashes/utils.js";

function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

function base64ToBytes(b64: string): Uint8Array {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

function bytesToUtf8(bytes: Uint8Array): string {
  let result = "";
  for (let i = 0; i < bytes.length; i++) {
    result += String.fromCharCode(bytes[i]);
  }
  return result;
}

class AesEncryption {
  /**
   * Encrypts a string value using AES-GCM with a secret key
   * @param value - The plaintext to encrypt
   * @param secret - The secret key (will be hashed with SHA-256)
   * @returns Base64-encoded encrypted data (iv + ciphertext + tag)
   */
  static async encrypt(
    value: string,
    secret: string,
    deterministicNonce = false,
  ): Promise<string> {
    try {
      const keyData = sha256(utf8ToBytes(secret));

      let iv: Uint8Array;
      if (deterministicNonce) {
        iv = hmac(sha256, keyData, utf8ToBytes(value)).slice(0, 12);
      } else {
        iv = randomBytes(12);
      }

      const encrypted = gcm(keyData, iv).encrypt(utf8ToBytes(value));
      return bytesToBase64(concatBytes(iv, encrypted));
    } catch (e) {
      throw new Error("Encryption failed: " + e);
    }
  }

  static async decrypt(
    encryptedValue: string,
    secret: string,
  ): Promise<string> {
    try {
      const encryptedData = base64ToBytes(encryptedValue);

      if (encryptedData.length < 28) {
        throw new Error("Invalid encrypted data: too short");
      }

      const keyData = sha256(utf8ToBytes(secret));
      const iv = encryptedData.slice(0, 12);
      const ciphertextWithTag = encryptedData.slice(12);

      const decrypted = gcm(keyData, iv).decrypt(ciphertextWithTag);
      return bytesToUtf8(decrypted);
    } catch (e) {
      throw new Error("Decryption failed: " + e);
    }
  }
}

export default AesEncryption;
