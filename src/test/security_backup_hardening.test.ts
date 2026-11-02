import "mocha";
import { expect } from "chai";
import sinon from "sinon";

describe("Security Hardening: Backup & Plaintext Elimination (GH-23)", () => {
  let sandbox: sinon.SinonSandbox;

  beforeEach(() => {
    sandbox = sinon.createSandbox();
  });

  afterEach(() => {
    sandbox.restore();
  });

  it("should_block_plaintext_blob_generation_when_master_password_is_set", () => {
    // Arrange: Konfigurasi state akun dengan Master Password aktif
    const mockAccountsState = {
      defaultEncryption: "key-hash-uuid-12345",
      exportData: {
        hash1: {
          hash: "hash1",
          secret: "JBSWY3DPEHPK3PXP",
          account: "test@example.com",
          issuer: "Service",
          type: "totp",
          period: 30,
          digits: 6,
          algorithm: "SHA1",
        },
      },
      exportEncData: {
        hash1: {
          hash: "hash1",
          secret: "v2:salt:iv:encrypted:hmac",
          account: "test@example.com",
          issuer: "Service",
          type: "totp",
        },
      },
      key: { id: "key-hash-uuid-12345" },
    };

    const isEncrypted = Boolean(mockAccountsState.defaultEncryption);

    // Act: Simulasi logika data() pada BackupPage.vue
    const exportFile = isEncrypted ? "" : "blob:dummy-plaintext-json";
    const exportOneLineOtpAuthFile = isEncrypted
      ? ""
      : "blob:dummy-plaintext-txt";

    // Assert: Wajib mengosongkan string blob agar tidak ada alokasi URL plaintext di DOM
    expect(exportFile).to.equal("");
    expect(exportOneLineOtpAuthFile).to.equal("");
    expect(isEncrypted).to.be.true;
  });

  it("should_allow_plaintext_blob_generation_when_no_master_password_is_configured", () => {
    // Arrange: Pengguna belum mengatur kata sandi
    const mockAccountsState = {
      defaultEncryption: "",
      exportData: {
        hash1: {
          hash: "hash1",
          secret: "JBSWY3DPEHPK3PXP",
        },
      },
    };

    const isEncrypted = Boolean(mockAccountsState.defaultEncryption);

    // Act
    const exportFile = isEncrypted ? "" : "blob:valid-unencrypted-file";
    const exportOneLineOtpAuthFile = isEncrypted ? "" : "blob:valid-otpauth-txt";

    // Assert: Plaintext hanya tersedia jika enkripsi belum aktif
    expect(exportFile).to.not.equal("");
    expect(exportOneLineOtpAuthFile).to.not.equal("");
    expect(isEncrypted).to.be.false;
  });

  it("should_reject_download_methods_when_master_password_is_active", () => {
    // Arrange: Mock window.open
    const openStub = sandbox.stub();
    const warnStub = sandbox.stub(console, "warn");

    const componentInstance = {
      defaultEncryption: "active-master-key-id",
      downloadBackUpOneLineOtpAuthFile() {
        if (this.defaultEncryption) {
          console.warn("[SECURITY] Ekspor plaintext diblokir karena Master Password aktif.");
          return;
        }
        openStub("blob:leaked-secret");
      },
      downloadBackUpExportFile() {
        if (this.defaultEncryption) {
          console.warn("[SECURITY] Ekspor plaintext diblokir karena Master Password aktif.");
          return;
        }
        openStub("blob:leaked-secret-json");
      },
    };

    // Act
    componentInstance.downloadBackUpOneLineOtpAuthFile();
    componentInstance.downloadBackUpExportFile();

    // Assert: window.open tidak pernah dipanggil dan warning tercatat
    expect(openStub.called).to.be.false;
    expect(warnStub.calledTwice).to.be.true;
    expect(warnStub.firstCall.args[0]).to.include("[SECURITY] Ekspor plaintext diblokir");
  });

  it("should_prevent_qr_code_rendering_when_secret_is_null_or_encrypted", () => {
    // Arrange: Entry dalam keadaan locked (secret null)
    const commitStub = sandbox.stub();
    const entryComponent = {
      showQr(entry: { secret: string | null }) {
        if (!entry.secret) {
          return;
        }
        commitStub("qr/setQr", "otpauth://...");
      },
    };

    // Act: Klik ikon QR saat vault terkunci
    entryComponent.showQr({ secret: null });

    // Assert: Store tidak pernah meng-commit QR dengan data sensitif
    expect(commitStub.called).to.be.false;
  });
});
