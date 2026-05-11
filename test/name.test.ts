import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { validatePosemeshName } from "../src/name.ts";

describe(".posemesh name validation", () => {
  it("accepts expected .posemesh names", () => {
    const names = [
      "nils.posemesh",
      "hq.posemesh",
      "americaNorth.posemesh",
      "relays.posemesh",
      "domains.posemesh",
    ];

    for (const name of names) {
      assert.equal(validatePosemeshName(name).ok, true);
    }
  });

  it("rejects names outside .posemesh", () => {
    const result = validatePosemeshName("example.hns");

    assert.equal(result.ok, false);
    assert.match(result.error ?? "", /\.posemesh/);
  });

  it("rejects the .posemesh root because the prototype always uses subnames", () => {
    const result = validatePosemeshName("posemesh");

    assert.equal(result.ok, false);
    assert.match(result.error ?? "", /subname/);
  });

  it("rejects empty labels and labels ending in hyphen", () => {
    for (const name of ["foo..posemesh", ".posemesh", "bad-.posemesh"]) {
      assert.equal(validatePosemeshName(name).ok, false, name);
    }
  });

});
