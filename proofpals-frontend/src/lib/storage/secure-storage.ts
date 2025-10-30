// src/lib/storage/secure-storage.ts
import { AES, enc } from 'crypto-js';

const STORAGE_KEY = 'proofpals_secure';

export class SecureStorage {
  private static getEncryptionKey(): string {
    // In production, derive from user passphrase or hardware key
    return sessionStorage.getItem('_ek') || '';
  }

  static async saveEncrypted(key: string, data: any): Promise<void> {
    const encryptionKey = this.getEncryptionKey();
    if (!encryptionKey) {
      console.warn('No encryption key available');
      return;
    }

    const encrypted = AES.encrypt(
      JSON.stringify(data),
      encryptionKey
    ).toString();

    localStorage.setItem(`${STORAGE_KEY}_${key}`, encrypted);
  }

  static async loadEncrypted(key: string): Promise<any> {
    const encryptionKey = this.getEncryptionKey();
    if (!encryptionKey) return null;

    const encrypted = localStorage.getItem(`${STORAGE_KEY}_${key}`);
    if (!encrypted) return null;

    try {
      const decrypted = AES.decrypt(encrypted, encryptionKey);
      return JSON.parse(decrypted.toString(enc.Utf8));
    } catch {
      return null;
    }
  }

  static clear(): void {
    Object.keys(localStorage)
      .filter(key => key.startsWith(STORAGE_KEY))
      .forEach(key => localStorage.removeItem(key));
  }
}