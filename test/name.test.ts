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

  it("rejects non-.posemesh names by default", () => {
    const result = validatePosemeshName("example.hns");

    assert.equal(result.ok, false);
    assert.match(result.error ?? "", /\.posemesh/);
  });

  it("accepts other Handshake names when allowAnyHandshakeName is true", () => {
    const result = validatePosemeshName("example.hns", {
      allowAnyHandshakeName: true,
    });

    assert.equal(result.ok, true);
    assert.equal(result.normalizedName, "example.hns");
  });
});
