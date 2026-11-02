import { expect } from "chai";
import { isInternalExtensionSender } from "../utils";

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
