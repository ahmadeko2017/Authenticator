import { expect } from "chai";
import * as CryptoJS from "crypto-js";
import { Encryption } from "../models/encryption";

describe("Security P2: Authenticated Encryption (AEAD) & Integrity Hardening", () => {
  const masterPassword = "SuperSecretMasterPassword123!";
  const keyId = "test-key-uuid-001";
  const sampleSecret = "JBSWY3DPEHPK3PXP";

  it("should_encrypt_with_v2_authenticated_encryption_format", () => {
    // Arrange
    const encryption = new Encryption(masterPassword, keyId);

    // Act
    const encrypted = encryption.getEncryptedString(sampleSecret);

    // Assert: Wajib berformat modern v2 dengan 5 segmen (v2:salt:iv:ciphertext:hmac)
    expect(encrypted).to.be.a("string");
    expect(encrypted.startsWith("v2:")).to.be.true;
    const parts = encrypted.split(":");
    expect(parts.length).to.equal(5);
    expect(parts[0]).to.equal("v2");
    expect(parts[1]).to.have.lengthOf(32); // 16-byte salt (hex)
    expect(parts[2]).to.have.lengthOf(32); // 16-byte IV (hex)
    expect(parts[4]).to.have.lengthOf(64); // 32-byte HMAC-SHA256 (hex)
  });

  it("should_decrypt_v2_ciphertext_successfully", () => {
    // Arrange
    const encryption = new Encryption(masterPassword, keyId);
    const encrypted = encryption.getEncryptedString(sampleSecret);

    // Act
    const decrypted = encryption.decryptSecretString(encrypted);

    // Assert: Dekripsi berhasil mengembalikan shared secret identik
    expect(decrypted).to.equal(sampleSecret);
  });

  it("should_reject_and_return_null_when_ciphertext_is_tampered", () => {
    // Arrange
    const encryption = new Encryption(masterPassword, keyId);
    const encrypted = encryption.getEncryptedString(sampleSecret);
    const parts = encrypted.split(":");

    // Manipulasi 1 karakter di payload ciphertext
    const corruptedCiphertext =
      parts[3].slice(0, -2) + (parts[3].slice(-2) === "AA" ? "BB" : "AA");
    const tamperedPayload = `v2:${parts[1]}:${parts[2]}:${corruptedCiphertext}:${parts[4]}`;

    // Act
    const decrypted = encryption.decryptSecretString(tamperedPayload);

    // Assert: Wajib ditolak (HMAC verification failure) dan mengembalikan null
    expect(decrypted).to.be.null;
  });

  it("should_decrypt_legacy_cryptojs_ciphertext_seamlessly", () => {
    // Arrange: Buat ciphertext legacy format CryptoJS (AES-CBC single MD5 KDF)
    const legacyCiphertext = CryptoJS.AES.encrypt(
      sampleSecret,
      masterPassword
    ).toString();
    const encryption = new Encryption(masterPassword, keyId);

    // Act
    const decrypted = encryption.decryptSecretString(legacyCiphertext);

    // Assert: Backward compatibility berjalan mulus, token legacy tetap terbaca
    expect(decrypted).to.equal(sampleSecret);
  });

  it("should_reject_decryption_with_incorrect_password", () => {
    // Arrange
    const encryptionValid = new Encryption(masterPassword, keyId);
    const encryptionWrong = new Encryption("WrongPassword999!", keyId);
    const encrypted = encryptionValid.getEncryptedString(sampleSecret);

    // Act
    const decrypted = encryptionWrong.decryptSecretString(encrypted);

    // Assert: Wajib gagal mengembalikan secret
    expect(decrypted).to.be.null;
  });

  it("should_return_original_data_when_no_password_is_configured", () => {
    // Arrange
    const encryptionEmpty = new Encryption("", keyId);

    // Act
    const result = encryptionEmpty.getEncryptedString(sampleSecret);

    // Assert: Mengembalikan data asli jika belum ada password
    expect(result).to.equal(sampleSecret);
    expect(encryptionEmpty.getEncryptionStatus()).to.be.false;
  });
});
