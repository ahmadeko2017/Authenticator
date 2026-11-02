import argon2 from "argon2-browser";

window.addEventListener("message", (event) => {
  const source = event.source as Window;
  if (!source) {
    return;
  }

  // Validasi keamanan: hanya proses pesan dari ekstensi yang sah
  const isExtensionOrigin =
    event.origin &&
    (event.origin.startsWith("chrome-extension://") ||
      event.origin.startsWith("moz-extension://"));

  if (!isExtensionOrigin) {
    return;
  }

  const message = event.data;
  if (!message || typeof message !== "object") {
    return;
  }

  switch (message.action) {
    case "hash":
      Argon.hash(message.value, message.salt)
        .then((hash) => {
          source.postMessage({ response: hash }, event.origin);
        })
        .catch((err) => {
          source.postMessage(
            { error: err?.message || "Argon hash failed" },
            event.origin
          );
        });
      break;

    case "verify":
      Argon.compareHash(message.hash, message.value)
        .then((result) => {
          source.postMessage({ response: result }, event.origin);
        })
        .catch((err) => {
          source.postMessage(
            { error: err?.message || "Argon verify failed" },
            event.origin
          );
        });
      break;

    default:
      break;
  }
  return;
});

class Argon {
  static async hash(value: string, salt: string | Uint8Array) {
    const hash = await argon2.hash({
      pass: value,
      salt: salt,
      time: 2,
      mem: 1024 * 19,
      parallelism: 1,
      hashLen: 32,
      type: argon2.ArgonType.Argon2id,
    });

    return hash.encoded;
  }

  static compareHash(hash: string, value: string) {
    return new Promise((resolve: (value: boolean) => void) => {
      argon2
        .verify({
          pass: value,
          encoded: hash,
        })
        .then(() => resolve(true))
        .catch((e: { message: string; code: number }) => {
          console.error("Error decoding hash", e);
          resolve(false);
        });
    });
  }
}
