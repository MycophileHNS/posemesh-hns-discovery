import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { MockResolver } from "../src/resolvers.ts";

describe("MockResolver", () => {
  it("resolves configured records case-insensitively", async () => {
    const resolver = new MockResolver({
      "hq.posemesh": ["posemesh:v1; capabilities=domain-discovery"],
    });

    assert.deepEqual(await resolver.resolveTxt("HQ.posemesh"), [
      "posemesh:v1; capabilities=domain-discovery",
    ]);
  });

  it("returns an empty list for missing records", async () => {
    const resolver = new MockResolver({});

    assert.deepEqual(await resolver.resolveTxt("missing.posemesh"), []);
  });
});
