import { expect } from "chai";
import { isMatchedEntry } from "../utils";
import { OTPEntry, OTPType } from "../models/otp";

describe("Domain Matcher Security Tests (Anti-Phishing & Origin Verification)", () => {
  const dummyEntry = (issuer: string) => {
    return new OTPEntry({
      account: "user@example.com",
      encrypted: false,
      index: 0,
      issuer,
      secret: "JBSWY3DPEHPK3PXP",
      type: OTPType.totp,
    });
  };

  it("should_reject_phishing_title_when_attacker_spoofs_title", () => {
    // Arrange: Situs phishing mencoba meniru judul tab "Google"
    const phishingSiteName = ["google", "evilphishing", "evil-phishing.com"];
    const googleEntry = dummyEntry("Google");

    // Act
    const isMatched = isMatchedEntry(phishingSiteName, googleEntry);

    // Assert: Wajib ditolak (tidak boleh cocok hanya karena <title>)
    expect(isMatched).to.be.false;
  });

  it("should_match_exact_domain_when_valid_host", () => {
    // Arrange: Situs asli Google
    const validSiteName = ["google", "google", "google.com"];
    const googleEntry = dummyEntry("Google");

    // Act
    const isMatched = isMatchedEntry(validSiteName, googleEntry);

    // Assert: Wajib cocok
    expect(isMatched).to.be.true;
  });

  it("should_match_valid_subdomain_when_explicit_host_defined", () => {
    // Arrange: Entri dengan konfigurasi host eksplisit "Google::accounts.google.com"
    const validSiteName = ["accounts", "google", "accounts.google.com"];
    const explicitEntry = dummyEntry("Google::accounts.google.com");

    // Act
    const isMatched = isMatchedEntry(validSiteName, explicitEntry);

    // Assert: Wajib cocok
    expect(isMatched).to.be.true;
  });

  it("should_match_domain_style_issuer", () => {
    // Arrange: Entri dengan issuer "github.com"
    const validSiteName = ["github", "github", "github.com"];
    const githubEntry = dummyEntry("github.com");

    // Act
    const isMatched = isMatchedEntry(validSiteName, githubEntry);

    // Assert: Wajib cocok
    expect(isMatched).to.be.true;
  });

  it("should_reject_attacker_domain_containing_brand_name", () => {
    // Arrange: Penyerang menggunakan nama domain "attackergoogle.com"
    const attackerSite = ["login", "attackergoogle", "attackergoogle.com"];
    const googleEntry = dummyEntry("Google");

    // Act
    const isMatched = isMatchedEntry(attackerSite, googleEntry);

    // Assert: Wajib ditolak (exact brand check)
    expect(isMatched).to.be.false;
  });
});
