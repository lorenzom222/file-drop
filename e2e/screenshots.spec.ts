import { test, expect } from "@playwright/test";
import { mkdirSync, readFileSync } from "node:fs";
import path from "node:path";

test("capture receiver and client documentation screenshots with dummy data", async ({ browser, browserName }) => {
  test.skip(browserName !== "chromium", "Capture one deterministic documentation image set.");
  const imageDir = path.resolve("docs/images");
  mkdirSync(imageDir, { recursive: true });
  const origin = "https://receiver.example-tailnet.ts.net";
  const context = await browser.newContext({ timezoneId: "UTC", locale: "en-US" });
  const files = [
    { name: "receipt.pdf", bytes: 184320, modified_at: "2026-11-01T12:00:00Z", id: "demo-receipt" },
    { name: "photo.jpg", bytes: 2400000, modified_at: "2026-11-01T11:45:00Z", id: "demo-photo" },
    { name: "notes.txt", bytes: 820, modified_at: "2026-11-01T11:30:00Z", id: "demo-notes" },
  ];
  const csp = "default-src 'none'; script-src 'self'; style-src 'self'; font-src 'self'; connect-src 'self'; img-src 'self' blob:; base-uri 'none'; frame-ancestors 'none'";
  try {
    await context.route("**/*", async route => {
      const url = new URL(route.request().url());
      if (url.origin !== origin) throw new Error("Documentation preview attempted an external request.");
      const json = (body: object, status = 200) => route.fulfill({ status, contentType: "application/json", body: JSON.stringify(body) });
      const asset: Record<string, [string, string]> = {
        "/owner": ["src/ui/owner.html", "text/html"],
        "/": ["src/ui/index.html", "text/html"],
        "/app.js": ["src/ui/dist/app.js", "text/javascript"],
        "/owner.js": ["src/ui/dist/owner.js", "text/javascript"],
        "/pairing.js": ["src/ui/dist/pairing.js", "text/javascript"],
        "/style.css": ["src/ui/style.css", "text/css"],
        "/fonts/jetbrains-mono.woff2": ["src/ui/fonts/jetbrains-mono.woff2", "font/woff2"],
      };
      const item = asset[url.pathname];
      if (item) {
        await route.fulfill({ contentType: item[1], body: readFileSync(path.resolve(item[0])), headers: { "Content-Security-Policy": csp } });
        return;
      }
      switch (url.pathname) {
      case "/api/owner/session":
        await json({ credential: "documentation-example-only", expires_at: "2026-11-01T20:00:00Z" });
        break;
      case "/api/owner/status":
        await json({ can_view_inbox: true, can_download: true, can_pair: true, state_dir: "/example/filedrop-state" });
        break;
      case "/api/owner/clients":
        await json({
          pending: [],
          clients: [{
            id: "1".repeat(64), name: "Example phone", fingerprint: "00112233445566778899aabbccddeeff",
            permission: "download", status: "active", last_seen: Date.parse("2026-11-01T12:00:00Z"),
          }],
        });
        break;
      case "/api/owner/invitations": {
        const body = route.request().postDataJSON();
        await json({ url: origin + "/#" + (body.mode === "remember" ? "pair=" : "") + "demo-invitation-not-valid", permission: body.permission, mode: body.mode, expires_at: new Date(Date.now() + 600000).toISOString() });
        break;
      }
      case "/api/session":
        await json({ max_file_bytes: 1073741824, can_view_inbox: true, can_download: true, can_upload: true });
        break;
      case "/api/inbox":
        await json({ files });
        break;
      case "/api/uploads":
        await json({ name: "receipt.pdf", bytes: 184320 }, 201);
        break;
      default:
        throw new Error(`Unexpected documentation request: ${url.pathname}`);
      }
    });
    const owner = await context.newPage();
    await owner.setViewportSize({ width: 1100, height: 1050 });
    await owner.goto(origin + "/owner#demo-owner-not-valid");
    await expect(owner.locator("#owner-panel")).toBeVisible();
    await owner.locator("#link-mode").selectOption("remember");
    await owner.locator("#pair-name").fill("Example laptop");
    await owner.locator("#permission").selectOption("download");
    await owner.getByRole("button", { name: "Create link", exact: true }).click();
    await expect(owner.locator("#invitation-url")).toHaveValue(/demo-invitation-not-valid/);
    await owner.evaluate(() => document.dispatchEvent(new Event("visibilitychange")));
    await expect(owner.locator("#paired-clients")).toContainText("Example phone");
    await owner.evaluate(async () => { await document.fonts.ready; });
    await owner.screenshot({ path: path.join(imageDir, "receiver.png"), fullPage: true, animations: "disabled" });

    const client = await context.newPage();
    await client.setViewportSize({ width: 390, height: 844 });
    await client.goto(origin + "/#demo-client-not-valid");
    await expect(client.locator("#upload-panel")).toBeVisible();
    await client.locator("#files").setInputFiles({ name: "receipt.pdf", mimeType: "application/pdf", buffer: Buffer.alloc(184320) });
    await client.getByRole("button", { name: "Upload 1 file", exact: true }).click();
    await expect(client.getByText("Saved: receipt.pdf", { exact: true })).toBeVisible();
    await expect(client.locator("#inbox-files tr")).toHaveCount(3);
    await client.evaluate(async () => { await document.fonts.ready; });
    await client.screenshot({ path: path.join(imageDir, "client.png"), fullPage: true, animations: "disabled" });
  } finally {
    await context.close();
  }
});
