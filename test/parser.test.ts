import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  parseAgentIdentityTxt,
  parsePosemeshTxt,
  parseTxtRecords,
} from "../src/parser.ts";

describe("TXT parsing", () => {
  it("parses compact posemesh:v1 records", () => {
    const parsed = parsePosemeshTxt(
      "posemesh:v1; manifest=https://example.com/posemesh.json; publicKey=BASE64_OR_HEX; capabilities=domain-discovery,relay-discovery",
    );

    assert.equal(parsed.kind, "posemesh");
    assert.equal(parsed.version, 1);
    assert.equal(parsed.manifestUrl, "https://example.com/posemesh.json");
    assert.deepEqual(parsed.publicKeys, ["BASE64_OR_HEX"]);
    assert.deepEqual(parsed.capabilities, ["domain-discovery", "relay-discovery"]);
  });

  it("parses agent-identity:v1 JSON records", () => {
    const parsed = parseAgentIdentityTxt(
      "agent-identity:v1={\"version\":1,\"endpoint\":\"https://example.com/agent.json\",\"capabilities\":[\"domain-discovery\",\"relay-discovery\"]}",
    );

    assert.equal(parsed.kind, "agent-identity");
    assert.equal(parsed.manifestUrl, "https://example.com/agent.json");
    assert.deepEqual(parsed.capabilities, ["domain-discovery", "relay-discovery"]);
  });

  it("reports malformed agent identity fields as warnings", () => {
    const result = parseTxtRecords([
      "agent-identity:v1={\"version\":1,\"endpoint\":\"http://example.com/agent.json\",\"capabilities\":[\"domain-discovery\"]}",
    ]);

    assert.equal(result.records.length, 0);
    assert.equal(result.warnings.length, 1);
    assert.match(result.warnings[0]?.message ?? "", /https/);
  });

  it("ignores unrelated TXT records and reports parse warnings", () => {
    const result = parseTxtRecords([
      "v=spf1 -all",
      "posemesh:v1; broken",
      "posemesh:v1; capabilities=relay-discovery",
    ]);

    assert.equal(result.records.length, 1);
    assert.equal(result.warnings.length, 1);
    assert.equal(result.warnings[0]?.record, "posemesh:v1; broken");
    assert.deepEqual(result.records[0]?.capabilities, ["relay-discovery"]);
  });
});
