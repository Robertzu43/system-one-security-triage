import assert from "node:assert/strict";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { canonicalJson, readJsonl, stableHash, writeJsonlExclusive } from "./jsonl.js";

test("atomic JSONL uses sorted compact JSON and refuses replacement", async () => {
  const root = await mkdtemp(join(tmpdir(), "jsonl-test-"));
  const target = join(root, "records.jsonl");
  try {
    assert.equal(canonicalJson({ b: 1, a: [true, { d: 2, c: "x" }] }), '{"a":[true,{"c":"x","d":2}],"b":1}');
    assert.equal(stableHash({ b: 1, a: 2 }), stableHash({ a: 2, b: 1 }));
    await writeJsonlExclusive(target, [{ b: 1, a: 2 }, ["x"]]);
    assert.equal(await readFile(target, "utf8"), '{"a":2,"b":1}\n["x"]\n');
    assert.deepEqual(await readJsonl(target, (value) => value), [{ a: 2, b: 1 }, ["x"]]);
    await assert.rejects(writeJsonlExclusive(target, []), /already exists/);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
