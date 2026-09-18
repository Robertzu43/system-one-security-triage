import { createHash } from "node:crypto";
import { copyFile, lstat, mkdir, readFile, readdir } from "node:fs/promises";
import { dirname, resolve, sep } from "node:path";
import { stableHash } from "./jsonl.js";

const excludedSegments = new Set([".git", "test", "tests", "__tests__", "advisories", "solutions", "challenges", "writeups", "patches", "private"]);
const excludedSuffixes = [".patch", ".diff"];
const forbiddenText = [/\bCVE-\d{4}-\d+\b/i, /vuln-code-snippet/i, /\bchallenge\b/i, /known vulnerable/i, /patched version/i];
const sensitivePathTerms = ["vulnerable", "patched", "challenge", "solution", "advisory", "writeup"];

export interface SanitizationPolicy { sourceCommit: string; }
export interface SnapshotFile { path: string; sha256: string; }
export interface SnapshotManifest { sourceCommit: string; policyHash: string; files: SnapshotFile[]; contentHash: string; }

const policyHash = stableHash({ excludedSegments: [...excludedSegments].sort(), excludedSuffixes, forbiddenText: forbiddenText.map((pattern) => pattern.toString()), sensitivePathTerms, excludedFilenamePatterns: ["*.test.*", "*.spec.*", "_test.*", ".env", ".env.*", "CVE-<year>-<id>"] });

function sensitiveSegment(segment: string): boolean {
  const lower = segment.toLowerCase();
  return excludedSegments.has(lower) || lower === ".env" || lower.startsWith(".env.") || lower.includes(".test.") || lower.includes(".spec.") || lower.startsWith("_test.") || /\bCVE-\d{4}-\d+\b/i.test(segment) || sensitivePathTerms.some((term) => lower.includes(term));
}
function excluded(path: string): boolean { return path.split("/").some(sensitiveSegment) || excludedSuffixes.some((suffix) => path.toLowerCase().endsWith(suffix)); }
function rejectLabels(path: string, content: Buffer): void {
  const text = content.toString("utf8");
  if (forbiddenText.some((pattern) => pattern.test(text))) throw new Error(`label leakage in ${path}`);
}
function digest(content: Buffer): string { return createHash("sha256").update(content).digest("hex"); }

async function assertDirectory(path: string): Promise<void> {
  const entry = await lstat(path);
  if (entry.isSymbolicLink()) throw new Error(`symbolic link rejected: ${path}`);
  if (!entry.isDirectory()) throw new Error(`expected directory: ${path}`);
}

async function assertSafeTree(root: string, current = ""): Promise<void> {
  const entries = await readdir(resolve(root, current), { withFileTypes: true });
  for (const entry of entries) {
    const path = current === "" ? entry.name : `${current}/${entry.name}`;
    if (entry.isSymbolicLink()) throw new Error(`symbolic link rejected: ${path}`);
    if (entry.isDirectory()) await assertSafeTree(root, path);
    else if (!entry.isFile()) throw new Error(`unsupported file type: ${path}`);
  }
}

async function walk(source: string, destination: string, current = "", files?: SnapshotFile[]): Promise<SnapshotFile[]> {
  const output = files ?? [];
  const entries = await readdir(resolve(source, current), { withFileTypes: true });
  for (const entry of entries.sort((left, right) => left.name < right.name ? -1 : left.name > right.name ? 1 : 0)) {
    const path = current === "" ? entry.name : `${current}/${entry.name}`;
    if (entry.isSymbolicLink()) throw new Error(`symbolic link rejected: ${path}`);
    if (excluded(path)) continue;
    const sourcePath = resolve(source, ...path.split("/"));
    const destinationPath = resolve(destination, ...path.split("/"));
    if (entry.isDirectory()) {
      await mkdir(destinationPath);
      await walk(source, destination, path, output);
    } else if (entry.isFile()) {
      const content = await readFile(sourcePath);
      rejectLabels(path, content);
      await mkdir(dirname(destinationPath), { recursive: true });
      await copyFile(sourcePath, destinationPath);
      output.push({ path, sha256: digest(content) });
    } else {
      throw new Error(`unsupported file type: ${path}`);
    }
  }
  return output;
}

export async function assertNoLabelLeakage(snapshot: string): Promise<void> {
  await assertDirectory(snapshot);
  async function scan(root: string, current = ""): Promise<void> {
    const entries = await readdir(resolve(root, current), { withFileTypes: true });
    for (const entry of entries) {
      const path = current === "" ? entry.name : `${current}/${entry.name}`;
      if (entry.isSymbolicLink()) throw new Error(`symbolic link rejected: ${path}`);
      const fullPath = resolve(root, ...path.split("/"));
      if (entry.isDirectory()) await scan(root, path);
      else if (entry.isFile()) rejectLabels(path, await readFile(fullPath));
      else throw new Error(`unsupported file type: ${path}`);
    }
  }
  await scan(snapshot);
}

export async function createSanitizedSnapshot(source: string, destination: string, policy: SanitizationPolicy): Promise<SnapshotManifest> {
  if (typeof policy.sourceCommit !== "string" || policy.sourceCommit.length === 0 || policy.sourceCommit.startsWith("/") || /^[A-Za-z]:[\\/]/.test(policy.sourceCommit)) throw new Error("sourceCommit must be non-empty and non-absolute");
  const sourceRoot = resolve(source);
  const destinationRoot = resolve(destination);
  if (destinationRoot === sourceRoot || destinationRoot.startsWith(`${sourceRoot}${sep}`)) throw new Error("snapshot destination must be outside source checkout");
  await assertDirectory(sourceRoot);
  await assertSafeTree(sourceRoot);
  await mkdir(destinationRoot);
  const files = await walk(sourceRoot, destinationRoot);
  await assertNoLabelLeakage(destinationRoot);
  return { sourceCommit: policy.sourceCommit, policyHash, files, contentHash: stableHash(files) };
}
