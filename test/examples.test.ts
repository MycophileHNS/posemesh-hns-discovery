import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { describe, it } from "node:test";

describe("examples", () => {
  it("runs the demo example with rich mock manifest data", () => {
    const result = spawnSync(
      process.execPath,
      ["--experimental-transform-types", "examples/demo.ts"],
      {
        cwd: process.cwd(),
        encoding: "utf8",
      },
    );

    assert.equal(result.status, 0, result.stderr || result.stdout);
    assert.match(result.stdout, /Posemesh HQ domain manager/);
    assert.doesNotMatch(result.stdout, /MANIFEST_SIGNATURE_REQUIRED/);
  });
});
