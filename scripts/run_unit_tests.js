const puppeteer = require("puppeteer");
const path = require("path");
const fs = require("fs");

async function main() {
  const browser = await puppeteer.launch({
    headless: "new",
    args: [
      "--no-sandbox",
      "--disable-setuid-sandbox",
      "--allow-file-access-from-files",
      "--disable-web-security"
    ]
  });

  const page = await browser.newPage();
  
  // Baca messages.json lokal untuk mock chrome.i18n
  const messagesPath = path.resolve(__dirname, "../_locales/en/messages.json");
  const messagesJson = JSON.parse(fs.readFileSync(messagesPath, "utf8"));

  // Mock chrome API environment
  await page.evaluateOnNewDocument((messages, messagesUrl) => {
    window.chrome = window.chrome || {};
    window.chrome.runtime = window.chrome.runtime || {
      getURL: (p) => messagesUrl,
      id: "bhghoamapcdpbohphigoooaddinpkbai",
      onMessage: { addListener: () => {} },
      sendMessage: () => {},
      getManifest: () => ({ version: "8.0.2" })
    };
    window.chrome.runtime.getManifest = () => ({ version: "8.0.2" });
    window.chrome.i18n = window.chrome.i18n || {
      getMessage: (key) => (messages[key] ? messages[key].message : key)
    };
    window.chrome.contextMenus = window.chrome.contextMenus || {
      create: () => {},
      removeAll: () => {},
      onClicked: { addListener: () => {} }
    };
    window.chrome.windows = window.chrome.windows || {
      create: () => {},
      getCurrent: async () => ({ id: 1 })
    };
    window.chrome.permissions = window.chrome.permissions || {
      contains: (q, cb) => (cb ? cb(true) : Promise.resolve(true)),
      request: (q, cb) => (cb ? cb(true) : Promise.resolve(true))
    };
    window.chrome.tabs = window.chrome.tabs || {
      create: (opts, cb) => (cb ? cb({ id: 2 }) : Promise.resolve({ id: 2 }))
    };
    window.chrome.storage = window.chrome.storage || {};
    window.chrome.storage.managed = {
      get: (keys, cb) => {
        const data = { feedbackURL: "https://example.com/feedback" };
        if (typeof keys === "function") {
          keys(data);
        } else if (typeof cb === "function") {
          cb(data);
        }
        return Promise.resolve(data);
      }
    };
    window.chrome.storage.local = {
      get: (k, cb) => (cb ? cb({}) : Promise.resolve({})),
      set: (data, cb) => (cb ? cb() : Promise.resolve())
    };
    window.chrome.storage.sync = {
      get: (k, cb) => (cb ? cb({}) : Promise.resolve({})),
      set: (data, cb) => (cb ? cb() : Promise.resolve())
    };
    window.chrome.storage.session = {
      get: (k, cb) => (cb ? cb({}) : Promise.resolve({})),
      set: (data, cb) => (cb ? cb() : Promise.resolve())
    };
  }, messagesJson, "file:///" + messagesPath.replace(/\\/g, "/"));

  const testHtmlPath = "file:///" + path.resolve(__dirname, "../view/test.html").replace(/\\/g, "/");
  console.log("Navigating to:", testHtmlPath);
  await page.goto(testHtmlPath);

  // Wait for testsComplete event or completed flag
  await page.waitForFunction(() => window.__mocha_test_results__ && window.__mocha_test_results__.completed === true, {
    timeout: 30000
  });

  const results = await page.evaluate(() => window.__mocha_test_results__);
  await browser.close();

  console.log("\n================ MOCHA TEST RESULTS ================");
  console.log(`Total Tests: ${results.total}`);
  
  let passed = 0;
  let failed = 0;

  for (const t of results.tests) {
    if (t.status === "passed") {
      passed++;
      console.log(`  ✓ [PASS] ${t.path.join(" > ")} (${t.duration}ms)`);
    } else {
      failed++;
      console.log(`  ✗ [FAIL] ${t.path.join(" > ")}: ${t.err}`);
    }
  }

  console.log("====================================================");
  console.log(`Passed: ${passed}, Failed: ${failed}`);

  if (failed > 0) {
    process.exit(1);
  }
}

main().catch(err => {
  console.error("Test execution failed:", err);
  process.exit(1);
});
