import { createHash } from "node:crypto";
import { link, lstat, open, readFile, rm, unlink } from "node:fs/promises";
import { dirname } from "node:path";

function canonicalValue(value: unknown, ancestors = new Set<object>()): unknown {
  if (value === null || typeof value === "string" || typeof value === "boolean") return value;
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new TypeError("canonical JSON requires finite numbers");
    return value;
  }
  if (Array.isArray(value)) {
    if (ancestors.has(value)) throw new TypeError("canonical JSON cannot contain cycles");
    ancestors.add(value);
    const result = value.map((item) => canonicalValue(item, ancestors));
    ancestors.delete(value);
    return result;
  }
  if (typeof value === "object") {
    if (ancestors.has(value)) throw new TypeError("canonical JSON cannot contain cycles");
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) throw new TypeError("canonical JSON requires plain objects");
    ancestors.add(value);
    const result: Record<string, unknown> = {};
    for (const key of Object.keys(value).sort()) result[key] = canonicalValue((value as Record<string, unknown>)[key], ancestors);
    ancestors.delete(value);
    return result;
  }
  throw new TypeError("canonical JSON requires JSON values");
}

export function canonicalJson(value: unknown): string {
  return JSON.stringify(canonicalValue(value));
}

export function stableHash(value: unknown): string {
  return createHash("sha256").update(canonicalJson(value), "utf8").digest("hex");
}

async function assertMissing(path: string): Promise<void> {
  try {
    await lstat(path);
  } catch (error: unknown) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return;
    throw error;
  }
  throw new Error(`artifact already exists: ${path}`);
}

async function syncDirectory(path: string): Promise<void> {
  let handle: Awaited<ReturnType<typeof open>> | undefined;
  try {
    handle = await open(path, "r");
    await handle.sync();
  } catch (error: unknown) {
    if (!new Set(["EINVAL", "ENOTSUP", "EISDIR", "EPERM"]).has((error as NodeJS.ErrnoException).code ?? "")) throw error;
  } finally {
    await handle?.close();
  }
}

export async function readJsonl<T>(path: string, parse: (value: unknown) => T): Promise<T[]> {
  const text = await readFile(path, "utf8");
  if (text === "") return [];
  const lines = text.endsWith("\n") ? text.slice(0, -1).split("\n") : text.split("\n");
  return lines.map((line) => parse(JSON.parse(line.endsWith("\r") ? line.slice(0, -1) : line)));
}

export async function writeJsonlExclusive(path: string, values: readonly unknown[]): Promise<void> {
  await assertMissing(path);
  const temporary = `${path}.tmp`;
  let created = false;
  try {
    const handle = await open(temporary, "wx");
    created = true;
    try {
      const contents = values.map(canonicalJson).join("\n");
      await handle.writeFile(contents === "" ? "" : `${contents}\n`, "utf8");
      await handle.sync();
    } finally {
      await handle.close();
    }
    await link(temporary, path);
    await unlink(temporary);
    created = false;
    await syncDirectory(dirname(path));
  } finally {
    if (created) await rm(temporary, { force: true });
  }
}
