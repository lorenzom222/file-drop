import { test, expect } from "@playwright/test";
import { spawn, execFileSync, ChildProcess } from "node:child_process";
import { mkdtempSync, realpathSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

test("pair, terminal-confirm, transfer, restart, reduce, increase and revoke", async ({ browser }, testInfo) => {
  const root = realpathSync(mkdtempSync(path.join(tmpdir(), "filedrop-e2e-")));
  const state = path.join(root, "state");
  const inbox = path.join(root, "inbox");
  const binary = path.resolve("bin/filedrop");
  const guestURL = "http://127.0.0.1:19444";
  const ownerURL = "http://127.0.0.1:19445";
  const contexts = [];
  let process: ChildProcess | undefined;
  let output = "";
  const start = async () => {
    output = "";
    process = spawn(binary, ["-dev-http", "-share-inbox", "-allow-downloads", "-listen", "127.0.0.1:19444", "-public-url", guestURL, "-owner-listen", "127.0.0.1:19445", "-state-dir", state, "-inbox", inbox]);
    process.stdout?.on("data", chunk => { output += chunk.toString(); });
    process.stderr?.on("data", chunk => { output += chunk.toString(); });
    await expect.poll(() => output, { timeout: 15000 }).toContain("Owner page");
    const ownerLink = output.match(/http:\/\/127\.0\.0\.1:19445\/#[a-f0-9]+/)?.[0];
    if (!ownerLink) throw new Error(`Receiver did not start: ${output}`);
    return ownerLink;
  };
  const stop = async () => {
    if (!process || process.exitCode !== null) return;
    const child = process;
    await new Promise<void>(resolve => { child.once("exit", () => resolve()); child.kill("SIGTERM"); });
  };
  const terminalConfirm = (id: string, offline = false) => {
    if (!offline && !/^[a-f0-9]{64}$/.test(id)) throw new Error("Invalid approval ID");
    // A real PTY exercises the CLI's interactive-terminal requirement.
    const script = `
import os, pty, select, subprocess, sys, time
master, slave = pty.openpty()
command = [sys.argv[1], sys.argv[4], '-state-dir', sys.argv[2]]
command += ['-offline'] if sys.argv[4] == 'reset-trust' else [sys.argv[3]]
p = subprocess.Popen(command, stdin=slave, stdout=slave, stderr=slave)
os.close(slave)
text = b''
deadline = time.time() + 15
answered = False
while time.time() < deadline and p.poll() is None:
    if select.select([master], [], [], .1)[0]:
        try: data = os.read(master, 8192)
        except OSError: break
        text += data
        if b'Type yes' in text and not answered:
            os.write(master, b'yes\\n')
            answered = True
if p.poll() is None:
    p.terminate()
code = p.wait(timeout=5)
os.close(master)
if code: raise SystemExit(text.decode(errors='replace'))
`;
    execFileSync("python3", ["-c", script, binary, state, id, offline ? "reset-trust" : "confirm"], { timeout: 25000 });
  };
  try {
    execFileSync(binary, ["init", "-state-dir", state]);
    const ownerContext = await browser.newContext();
    const guestContext = await browser.newContext(testInfo.project.name === "webkit-mobile"
      ? { viewport: { width: 390, height: 844 }, isMobile: true, hasTouch: true, deviceScaleFactor: 3 }
      : {});
    contexts.push(ownerContext, guestContext);
    const owner = await ownerContext.newPage();
    const guest = await guestContext.newPage();
    await owner.goto(await start());
    await expect(owner.locator("#owner-panel")).toBeVisible();
    await owner.locator("#link-mode").selectOption("remember");
    await owner.locator("#pair-name").fill("E2E browser");
    await owner.locator("#permission").selectOption("download");
    await owner.getByRole("button", { name: "Create link", exact: true }).click();
    await expect(owner.locator("#invitation-url")).toHaveValue(/#pair=/);
    const link = await owner.locator("#invitation-url").inputValue();
    await guest.goto(link);
    await guest.getByRole("button", { name: "Request pairing", exact: true }).click();
    await expect(guest.locator("#pair-status")).toContainText("Waiting for terminal approval");
    await expect.poll(async () => {
      await owner.evaluate(() => document.dispatchEvent(new Event("visibilitychange")));
      return owner.locator("#pending-approvals code").count();
    }).toBe(1);
    const command = await owner.locator("#pending-approvals code").innerText();
    const id = command.match(/[a-f0-9]{64}$/)?.[0];
    if (!id) throw new Error("Approval command missing ID");
    terminalConfirm(id);
    await expect(guest.locator("#upload-panel")).toBeVisible();
    await guest.locator("#files").setInputFiles({ name: "roundtrip.txt", mimeType: "text/plain", buffer: Buffer.from("paired transfer") });
    await guest.getByRole("button", { name: "Upload 1 file", exact: true }).click();
    await expect(guest.getByText("Saved: roundtrip.txt", { exact: true })).toBeVisible();
    expect(readFileSync(path.join(inbox, "roundtrip.txt"), "utf8")).toBe("paired transfer");
    await expect(guest.getByRole("link", { name: "Download roundtrip.txt", exact: true })).toBeVisible();
    const [download] = await Promise.all([
      guest.waitForEvent("download"),
      guest.getByRole("link", { name: "Download roundtrip.txt", exact: true }).click(),
    ]);
    const downloaded = path.join(root, "downloaded.txt");
    await download.saveAs(downloaded);
    expect(readFileSync(downloaded, "utf8")).toBe("paired transfer");
    // Key is persisted but nonextractable; the user returns to the ordinary URL.
    await guest.reload();
    await expect(guest.locator("#upload-panel")).toBeVisible();
    await guest.goto(guestURL + "/#pair=" + "0".repeat(64));
    await guest.getByRole("button", { name: "Request pairing", exact: true }).click();
    await expect(guest.locator("#pair-status")).toContainText("Pairing authentication failed");
    await guest.goto(guestURL);
    await expect(guest.locator("#upload-panel")).toBeVisible();
    await stop();
    const ownerLink = await start();
    await guest.reload();
    await expect(guest.locator("#upload-panel")).toBeVisible();
    await owner.goto(ownerLink);
    await owner.reload();
    await expect(owner.locator("#owner-panel")).toBeVisible();
    await expect.poll(async () => {
      await owner.evaluate(() => document.dispatchEvent(new Event("visibilitychange")));
      return owner.locator("#paired-clients .paired-entry").count();
    }).toBe(1);
    const row = owner.locator("#paired-clients .paired-entry").first();
    await row.locator("select").selectOption("upload");
    await row.getByRole("button", { name: "Save access", exact: true }).click();
    await guest.reload();
    await expect(guest.locator("#upload-panel")).toBeVisible();
    await expect(guest.locator("#inbox")).toBeHidden();
    await expect.poll(async () => {
      await owner.evaluate(() => document.activeElement instanceof HTMLElement && document.activeElement.blur());
      await owner.evaluate(() => document.dispatchEvent(new Event("visibilitychange")));
      return row.locator("select").inputValue();
    }).toBe("upload");
    await row.locator("select").selectOption("download");
    await row.getByRole("button", { name: "Save access", exact: true }).click();
    await expect.poll(async () => {
      await owner.evaluate(() => document.activeElement instanceof HTMLElement && document.activeElement.blur());
      await owner.evaluate(() => document.dispatchEvent(new Event("visibilitychange")));
      return owner.locator("#pending-approvals code").count();
    }).toBe(1);
    const increase = (await owner.locator("#pending-approvals code").innerText()).match(/[a-f0-9]{64}$/)?.[0];
    if (!increase) throw new Error("Missing increase confirmation ID");
    terminalConfirm(increase);
    await guest.reload();
    await expect(guest.getByRole("link", { name: "Download roundtrip.txt", exact: true })).toBeVisible();
    await row.getByRole("button", { name: "Revoke", exact: true }).click();
    await expect.poll(async () => readFileSync(path.join(inbox, "roundtrip.txt"), "utf8")).toBe("paired transfer");
    await guest.reload();
    await expect(guest.locator("#upload-panel")).toBeHidden();
    await expect(guest.locator("#connection")).toContainText("Pairing authentication failed");
    await stop();
    await start();
    await guest.reload();
    await expect(guest.locator("#upload-panel")).toBeHidden();
    await stop();
    terminalConfirm("", true);
    await start();
    await guest.reload();
    await expect(guest.locator("#connection")).toContainText("Receiver trust changed");
  } finally {
    for (const context of contexts) await context.close();
    await stop();
    rmSync(root, { recursive: true, force: true });
  }
});
