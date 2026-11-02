/**
 * Konfigurasi Kredensial OAuth Provider (Google Drive, Dropbox, OneDrive).
 *
 * CATATAN KEAMANAN & ARSITEKTUR (HIGH-03):
 * 1. Ekstensi peramban merupakan "Public Client" (RFC 6749 Section 2.1).
 *    DILARANG MENYIMPAN client_secret asli di repositori kode sumber publik.
 * 2. Untuk deployment produksi mandiri:
 *    - Gunakan alur OAuth 2.0 PKCE (RFC 7636) atau API chrome.identity.launchWebAuthFlow.
 *    - Jangan pernah meng-commit file credentials.ts dengan secret nyata ke git history.
 */
export function getCredentials() {
  return {
    drive: {
      client_id: "", // Google client ID (Public Client)
      client_secret: "", // Dikosongkan demi keamanan (Gunakan alur PKCE)
    },
    dropbox: {
      client_id: "", // Dropbox client ID (Public App Key)
    },
    onedrive: {
      client_id: "", // Microsoft Identity client ID (SPA/Public Client)
      client_secret: "", // Dikosongkan demi keamanan (Gunakan alur PKCE)
    },
  };
}
