import assert from "node:assert/strict";
import { cp, mkdir, mkdtemp, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { assertNoLabelLeakage, createSanitizedSnapshot, type SanitizationPolicy } from "./sanitize.js";

const fixture = "test/fixtures/repository/leaky";
const policy: SanitizationPolicy = { sourceCommit: "0123456789abcdef" };

async function checkout(): Promise<{ root: string; source: string; destination: string }> {
  const root = await mkdtemp(join(tmpdir(), "snapshot-test-"));
  const source = join(root, "source");
  await cp(fixture, source, { recursive: true });
  return { root, source, destination: join(root, "snapshot") };
}

test("snapshot copies code bytes and excludes label-bearing repository material", async () => {
  const { root, source, destination } = await checkout();
  try {
    await mkdir(join(source, ".git"));
    await writeFile(join(source, ".git", "config"), "private history");
    await writeFile(join(source, "fix.patch"), "patched version");
    await writeFile(join(source, "notes.diff"), "known vulnerable");
    const manifest = await createSanitizedSnapshot(source, destination, policy);
    assert.deepEqual(await readFile(join(destination, "src", "route.ts")), await readFile(join(source, "src", "route.ts")));
    assert.deepEqual(manifest.files.map((file) => file.path), ["src/private-api.ts", "src/route.ts"]);
    assert.match(manifest.files[0]!.sha256, /^[a-f0-9]{64}$/);
    assert.match(manifest.contentHash, /^[a-f0-9]{64}$/);
    assert.equal(manifest.sourceCommit, policy.sourceCommit);
    assert.equal(JSON.stringify(manifest).includes(source), false);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("snapshot excludes sensitive filenames even when their contents are safe", async () => {
  const { root, source, destination } = await checkout();
  try {
    const manifest = await createSanitizedSnapshot(source, destination, policy);
    const sensitive = ["src/route.test.ts", "src/route.spec.ts", "src/_test.ts", "src/.env", "src/.env.local", "src/CVE-2025-0001.ts", "src/known-vulnerable.ts", "src/patched-route.ts", "src/challenge-route.ts", "src/solution-route.ts", "src/advisory-route.ts", "src/writeup-route.ts", "private/secret.ts"];
    assert.deepEqual(manifest.files.map((file) => file.path), ["src/private-api.ts", "src/route.ts"]);
    for (const path of sensitive) assert.equal(manifest.files.some((file) => file.path === path), false);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("snapshot excludes key artifacts and label-marker filenames with safe contents", async () => {
  const { root, source, destination } = await checkout();
  try {
    const manifest = await createSanitizedSnapshot(source, destination, policy);
    const sensitive = ["src/vuln-code-snippet.ts", "src/private-key.ts", "src/private_key.ts", "src/secret-key.ts", "src/secret_key.ts", "src/certificate.key", "src/certificate.pem", "src/archive.p12", "src/archive.pfx"];
    for (const path of sensitive) assert.equal(manifest.files.some((file) => file.path === path), false);
    assert.equal(manifest.files.some((file) => file.path === "src/private-api.ts"), true);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("snapshot file ordering and aggregate hash use deterministic code-unit order", async () => {
  const { root, source, destination } = await checkout();
  try {
    await writeFile(join(source, "src", "Z.ts"), "export const upper = true;");
    await writeFile(join(source, "src", "a.ts"), "export const lower = true;");
    const first = await createSanitizedSnapshot(source, destination, policy);
    const second = await createSanitizedSnapshot(source, join(root, "snapshot-again"), policy);
    assert.deepEqual(first.files.map((file) => file.path), ["src/Z.ts", "src/a.ts", "src/private-api.ts", "src/route.ts"]);
    assert.equal(first.contentHash, second.contentHash);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("snapshot rejects a symbolic link instead of following it", async () => {
  const { root, source, destination } = await checkout();
  try {
    await symlink(join(source, "src", "route.ts"), join(source, "src", "linked.ts"));
    await assert.rejects(createSanitizedSnapshot(source, destination, policy), /symbolic link/);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("snapshot rejects a symbolic link even inside excluded material", async () => {
  const { root, source, destination } = await checkout();
  try {
    await symlink(join(source, "src", "route.ts"), join(source, "tests", "linked.ts"));
    await assert.rejects(createSanitizedSnapshot(source, destination, policy), /symbolic link/);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("snapshot rejects every frozen label marker in included text", async () => {
  const labels = ["CVE-2025-0001", "vuln-code-snippet", "challenge", "known vulnerable", "patched version"];
  for (const label of labels) {
    const { root, source, destination } = await checkout();
    try {
      await writeFile(join(source, "src", "label.ts"), `export const label = ${JSON.stringify(label)};`);
      await assert.rejects(createSanitizedSnapshot(source, destination, policy), /label leakage/);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  }
});

test("leakage scan rejects labels introduced after snapshot creation", async () => {
  const { root, source, destination } = await checkout();
  try {
    await createSanitizedSnapshot(source, destination, policy);
    await writeFile(join(destination, "src", "late.ts"), "// known vulnerable");
    await assert.rejects(assertNoLabelLeakage(destination), /label leakage/);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("snapshot never emits an absolute source path as its commit metadata", async () => {
  const { root, source, destination } = await checkout();
  try {
    await assert.rejects(createSanitizedSnapshot(source, destination, { sourceCommit: source }), /sourceCommit/);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
