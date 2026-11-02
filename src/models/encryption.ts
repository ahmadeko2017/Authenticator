/**
 * Modul Enkripsi Terotentikasi (Authenticated Encryption)
 * Menggunakan kombinasi PBKDF2-HMAC-SHA256 (10.000 iterasi), AES-256-CBC,
 * dan HMAC-SHA256 (Encrypt-then-MAC) untuk proteksi integritas dan kerahasiaan shared secret.
 */
import * as CryptoJS from "crypto-js";

export class Encryption implements EncryptionInterface {
  private password: string;
  private keyId: string;

  constructor(hash: string, keyId: string) {
    this.password = hash;
    this.keyId = keyId;
  }

  /**
   * Mengenkripsi string data dengan skema terotentikasi v2.
   * Format keluaran: v2:salt_hex:iv_hex:ciphertext_base64:hmac_hex
   */
  getEncryptedString(data: string): string {
    if (!this.password) {
      return data;
    }

    try {
      const salt = CryptoJS.lib.WordArray.random(16);
      const iv = CryptoJS.lib.WordArray.random(16);
      const derivedKey = CryptoJS.PBKDF2(this.password, salt, {
        keySize: 256 / 32,
        iterations: 10000,
      });

      const encrypted = CryptoJS.AES.encrypt(data, derivedKey, {
        iv: iv,
        mode: CryptoJS.mode.CBC,
        padding: CryptoJS.pad.Pkcs7,
      });

      const saltHex = salt.toString(CryptoJS.enc.Hex);
      const ivHex = iv.toString(CryptoJS.enc.Hex);
      const cipherText = encrypted.toString();

      // Hitung HMAC-SHA256 atas metadata dan ciphertext (Encrypt-then-MAC)
      const hmac = CryptoJS.HmacSHA256(
        saltHex + ":" + ivHex + ":" + cipherText,
        derivedKey
      ).toString(CryptoJS.enc.Hex);

      return `v2:${saltHex}:${ivHex}:${cipherText}:${hmac}`;
    } catch (error) {
      console.error("[ENCRYPTION] Gagal mengenkripsi payload:", error);
      return data;
    }
  }

  /**
   * Mendekripsi shared secret TOTP dan memvalidasi format string Base32/Hex.
   */
  decryptSecretString(secret: string): string | null {
    try {
      const decryptedSecret = this.decryptInternal(secret);
      if (!decryptedSecret || decryptedSecret.length < 8) {
        return null;
      }

      if (
        !/^[a-z2-7]+=*$/i.test(decryptedSecret) &&
        !/^[0-9a-f]+$/i.test(decryptedSecret) &&
        !/^blz-/.test(decryptedSecret) &&
        !/^bliz-/.test(decryptedSecret) &&
        !/^stm-/.test(decryptedSecret)
      ) {
        return null;
      }

      return decryptedSecret;
    } catch (error) {
      return null;
    }
  }

  /**
   * Mendekripsi payload objek OTP tersimpan.
   */
  decryptEncSecret(entry: OTPEntryInterface): RawOTPStorage | null {
    try {
      if (!entry.encData) {
        return null;
      }

      const decryptedData = this.decryptInternal(entry.encData);
      if (!decryptedData) {
        return null;
      }

      return JSON.parse(decryptedData);
    } catch (error) {
      return null;
    }
  }

  /**
   * Dekripsi internal yang mendukung format modern v2 dan format warisan (legacy).
   */
  private decryptInternal(ciphertext: string): string | null {
    if (!this.password || !ciphertext) {
      return null;
    }

    // 1. Verifikasi dan dekripsi format modern v2
    if (ciphertext.startsWith("v2:")) {
      return this.decryptV2(ciphertext);
    }

    // 2. Fallback graceful ke format CryptoJS legacy lama
    try {
      const legacyDecrypted = CryptoJS.AES.decrypt(
        ciphertext,
        this.password
      ).toString(CryptoJS.enc.Utf8);
      return legacyDecrypted || null;
    } catch {
      return null;
    }
  }

  /**
   * Dekripsi format v2 dengan verifikasi HMAC sebelum operasi dekripsi.
   */
  private decryptV2(ciphertext: string): string | null {
    const parts = ciphertext.split(":");
    if (parts.length !== 5) {
      return null;
    }

    const [, saltHex, ivHex, encData, expectedHmac] = parts;
    const salt = CryptoJS.enc.Hex.parse(saltHex);
    const iv = CryptoJS.enc.Hex.parse(ivHex);

    const derivedKey = CryptoJS.PBKDF2(this.password, salt, {
      keySize: 256 / 32,
      iterations: 10000,
    });

    const computedHmac = CryptoJS.HmacSHA256(
      saltHex + ":" + ivHex + ":" + encData,
      derivedKey
    ).toString(CryptoJS.enc.Hex);

    if (computedHmac !== expectedHmac) {
      console.warn("[SECURITY GUARD] Verifikasi HMAC gagal! Data telah dimanipulasi.");
      return null;
    }

    const decrypted = CryptoJS.AES.decrypt(encData, derivedKey, {
      iv: iv,
      mode: CryptoJS.mode.CBC,
      padding: CryptoJS.pad.Pkcs7,
    }).toString(CryptoJS.enc.Utf8);

    return decrypted || null;
  }

  getEncryptionStatus(): boolean {
    return Boolean(this.password);
  }

  updateEncryptionPassword(password: string): void {
    this.password = password;
  }

  setEncryptionKeyId(id: string): void {
    this.keyId = id;
  }

  getEncryptionKeyId(): string {
    return this.keyId;
  }
}
