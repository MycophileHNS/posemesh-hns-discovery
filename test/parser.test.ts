import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  parseAgentIdentityTxt,
  parsePosemeshTxt,
  parseTxtRecords,
} from "../src/parser.ts";

const TXT_PUBLIC_KEY = "02aa";
const AGENT_PUBLIC_KEY = "QUJDRA==";

describe("TXT parsing", () => {
  it("parses compact posemesh:v1 records", () => {
    const parsed = parsePosemeshTxt(
      `posemesh:v1; manifest=https://example.com/posemesh.json; publicKey=${TXT_PUBLIC_KEY}; capabilities=domain-discovery,relay-discovery`,
    );

    assert.equal(parsed.kind, "posemesh");
    assert.equal(parsed.version, 1);
    assert.equal(parsed.manifestUrl, "https://example.com/posemesh.json");
    assert.deepEqual(parsed.publicKeys, [TXT_PUBLIC_KEY]);
    assert.deepEqual(parsed.capabilities, ["domain-discovery", "relay-discovery"]);
  });

  it("parses multiple TXT verification keys with rotation windows", () => {
    const parsed = parsePosemeshTxt(
      `posemesh:v1; publicKey=${TXT_PUBLIC_KEY}; publicKeys=03bb,04cc; keyId=rotating-key; alg=ed25519; notBefore=2026-05-12T00:00:00.000Z; notAfter=2026-05-13T00:00:00.000Z`,
    );

    assert.deepEqual(parsed.publicKeys, [TXT_PUBLIC_KEY, "03bb", "04cc"]);
    assert.equal(parsed.verificationKeys.length, 3);
    assert.equal(parsed.verificationKeys[0]?.id, "rotating-key");
    assert.equal(parsed.verificationKeys[0]?.notBefore, "2026-05-12T00:00:00.000Z");
    assert.equal(parsed.verificationKeys[0]?.notAfter, "2026-05-13T00:00:00.000Z");
  });

  it("parses agent-identity:v1 JSON records", () => {
    const parsed = parseAgentIdentityTxt(
      `agent-identity:v1={"version":1,"endpoint":"https://example.com/agent.json","publicKey":"${AGENT_PUBLIC_KEY}","capabilities":["domain-discovery","relay-discovery"]}`,
    );

    assert.equal(parsed.kind, "agent-identity");
    assert.equal(parsed.agentEndpointUrl, "https://example.com/agent.json");
    assert.equal(parsed.manifestUrl, undefined);
    assert.deepEqual(parsed.publicKeys, [AGENT_PUBLIC_KEY]);
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
      `posemesh:v1; publicKey=${TXT_PUBLIC_KEY}; capabilities=relay-discovery`,
    ]);

    assert.equal(result.records.length, 1);
    assert.equal(result.warnings.length, 1);
    assert.equal(result.warnings[0]?.record, "posemesh:v1; broken");
    assert.deepEqual(result.records[0]?.publicKeys, [TXT_PUBLIC_KEY]);
    assert.deepEqual(result.records[0]?.capabilities, ["relay-discovery"]);
  });

  it("rejects malformed public keys", () => {
    const result = parseTxtRecords([
      "posemesh:v1; publicKey=not_a_hex_or_base64_key; capabilities=relay-discovery",
    ]);

    assert.equal(result.records.length, 0);
    assert.equal(result.warnings.length, 1);
    assert.match(result.warnings[0]?.message ?? "", /hex or base64/);
  });
});
