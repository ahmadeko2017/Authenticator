import { expect } from "chai";
import { isInternalExtensionSender } from "../utils";
import { BrowserStorage } from "../models/storage";

describe("Security P1: Service Worker Message Sender Validation", () => {
  it("should_reject_sender_when_message_originates_from_web_tab", () => {
    // Arrange: Pengirim adalah content script di dalam tab halaman web
    const tabSender = {
      id: "bhghoamapcdpbohphigoooaddinpkbai",
      url: "https://evil-attacker.com/login",
      tab: {
        id: 101,
        index: 0,
        pinned: false,
        highlighted: false,
        windowId: 1,
        active: true,
        incognito: false,
        selected: true,
        discarded: false,
        autoDiscardable: true,
        groupId: -1,
      },
    } as chrome.runtime.MessageSender;

    // Act
    const isAllowed = isInternalExtensionSender(tabSender);

    // Assert: Wajib ditolak (content script dilarang mengeksekusi aksi administratif)
    expect(isAllowed).to.be.false;
  });

  it("should_accept_sender_when_message_originates_from_internal_extension_page", () => {
    // Arrange: Pengirim adalah popup internal ekstensi
    const extensionId = chrome.runtime.id;
    const internalSender = {
      id: extensionId,
      url: `chrome-extension://${extensionId}/view/popup.html`,
    } as chrome.runtime.MessageSender;

    // Act
    const isAllowed = isInternalExtensionSender(internalSender);

    // Assert: Wajib diizinkan
    expect(isAllowed).to.be.true;
  });

  it("should_reject_sender_when_url_is_missing_or_external", () => {
    // Arrange: Pengirim dengan URL eksternal tanpa tab
    const externalSender = {
      id: "other-extension-id",
      url: "https://malicious-site.com",
    } as chrome.runtime.MessageSender;

    // Act
    const isAllowed = isInternalExtensionSender(externalSender);

    // Assert: Wajib ditolak
    expect(isAllowed).to.be.false;
  });
});

describe("Security P1: Cloud Sync Plaintext Secret Guard", () => {
  it("should_detect_unencrypted_secret_in_storage_payload", () => {
    // Arrange: payload dengan secret unencrypted
    const rawPayload = {
      "hash-1": {
        account: "alice@example.com",
        secret: "JBSWY3DPEHPK3PXP",
        encrypted: false,
      },
    };

    // Act
    const hasUnencrypted = BrowserStorage.containsUnencryptedSecrets(rawPayload);

    // Assert: Wajib terdeteksi true
    expect(hasUnencrypted).to.be.true;
  });

  it("should_not_flag_payload_when_secrets_are_properly_encrypted", () => {
    // Arrange: payload yang sudah dienkripsi
    const encryptedPayload = {
      "hash-2": {
        dataType: "EncOTPStorage",
        data: "encrypted-ciphertext-blob",
        keyId: "key-1",
        encrypted: true,
      },
    };

    // Act
    const hasUnencrypted = BrowserStorage.containsUnencryptedSecrets(encryptedPayload);

    // Assert: Wajib false
    expect(hasUnencrypted).to.be.false;
  });

  it("should_not_flag_settings_payload_without_secrets", () => {
    // Arrange: UserSettings biasa tanpa secret OTP
    const settingsPayload = {
      theme: "dark",
      zoom: 100,
    };

    // Act
    const hasUnencrypted = BrowserStorage.containsUnencryptedSecrets(settingsPayload);

    // Assert: Wajib false
    expect(hasUnencrypted).to.be.false;
  });
});
