import { BrowserStorage, isOldKey } from "./storage";

async function sendArgonMessage<T>(message: object): Promise<T> {
  const iframe = document.getElementById("argon-sandbox") as HTMLIFrameElement;
  const contentWindow = iframe?.contentWindow;
  if (!iframe || !contentWindow) {
    throw new Error("argon-sandbox missing!");
  }

  return new Promise((resolve) => {
    const handler = (event: MessageEvent) => {
      // Validasi origin & source: hanya terima respons dari sandbox iframe milik sendiri
      if (event.source !== contentWindow) {
        return;
      }
      window.removeEventListener("message", handler);
      resolve(event.data?.response);
    };

    window.addEventListener("message", handler);
    contentWindow.postMessage(message, "*");
  });
}

export async function argonHash(
  value: string,
  salt: string
): Promise<string | undefined> {
  return sendArgonMessage<string | undefined>({
    action: "hash",
    value,
    salt,
  });
}

export async function argonVerify(
  value: string,
  hash: string
): Promise<boolean> {
  return sendArgonMessage<boolean>({
    action: "verify",
    value,
    hash,
  });
}

// Verify a password using keys in BrowserStorage
export async function verifyPasswordUsingKeyID(
  keyId: string,
  password: string
): Promise<boolean> {
  // Get key for current encryption
  const keys = await BrowserStorage.getKeys();
  if (isOldKey(keys)) {
    throw new Error(
      "v3 encryption not being used with verifyPassword. This should never happen!"
    );
  }

  const key = keys.find((key) => key.id === keyId);
  if (!key) {
    throw new Error(`Key ${keyId} not in BrowserStorage`);
  }

  return verifyPasswordUsingKey(key, password);
}

export async function verifyPasswordUsingKey(
  key: Key,
  password: string
): Promise<boolean> {
  // Hash password with argon
  const rawHash = await argonHash(password, key.salt);
  if (!rawHash) {
    throw new Error("argon2 did not return a hash!");
  }
  // https://passlib.readthedocs.io/en/stable/lib/passlib.hash.argon2.html#format-algorithm
  const possibleHash = rawHash.split("$")[5];

  // verify user password by comparing their password hash with the
  // hash of their password's hash
  return await argonVerify(possibleHash, key.hash);
}
