import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  parseAgentIdentityTxt,
  parsePosemeshTxt,
  parseTxtRecords,
} from "../src/parser.ts";

const TXT_PUBLIC_KEY = "aa".repeat(32);
const TXT_PUBLIC_KEY_TWO = "bb".repeat(32);
const TXT_PUBLIC_KEY_THREE = "cc".repeat(32);
const AGENT_PUBLIC_KEY = "dd".repeat(32);

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
      `posemesh:v1; publicKey=${TXT_PUBLIC_KEY}; publicKeys=${TXT_PUBLIC_KEY_TWO},${TXT_PUBLIC_KEY_THREE}; keyId=rotating-key; alg=ed25519; notBefore=2026-05-12T00:00:00.000Z; notAfter=2026-05-13T00:00:00.000Z`,
    );

    assert.deepEqual(parsed.publicKeys, [TXT_PUBLIC_KEY, TXT_PUBLIC_KEY_TWO, TXT_PUBLIC_KEY_THREE]);
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
    assert.equal(result.warnings[0]?.code, "TXT_PARSE_ERROR");
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
    assert.equal(result.warnings[0]?.code, "TXT_PARSE_ERROR");
    assert.deepEqual(result.records[0]?.publicKeys, [TXT_PUBLIC_KEY]);
    assert.deepEqual(result.records[0]?.capabilities, ["relay-discovery"]);
  });

  it("rejects malformed public keys", () => {
    const result = parseTxtRecords([
      "posemesh:v1; publicKey=not_a_hex_or_base64_key; capabilities=relay-discovery",
    ]);

    assert.equal(result.records.length, 0);
    assert.equal(result.warnings.length, 1);
    assert.equal(result.warnings[0]?.code, "MANIFEST_PUBLIC_KEY_INVALID");
    assert.match(result.warnings[0]?.message ?? "", /hex or base64/);
  });

  it("enforces TXT parser limits", () => {
    assert.throws(
      () => parseTxtRecords(["v=spf1 -all", "v=spf1 -all"], { maxTxtRecords: 1 }),
      /TXT records exceeds limit 1/,
    );

    const result = parseTxtRecords(
      [
        `posemesh:v1; publicKey=${TXT_PUBLIC_KEY}; capabilities=${"a".repeat(16)}`,
      ],
      { maxFieldValueBytes: 8 },
    );

    assert.equal(result.records.length, 0);
    assert.equal(result.warnings[0]?.code, "TXT_LIMIT_EXCEEDED");
    assert.match(result.warnings[0]?.message ?? "", /exceeds 8 bytes/);
  });

  it("supports optional redacted parser logging", () => {
    const warnFields: unknown[] = [];
    const logger = {
      debug: () => undefined,
      info: () => undefined,
      warn: (_message: string, fields?: unknown) => warnFields.push(fields),
      error: () => undefined,
    };

    parseTxtRecords(["posemesh:v1; publicKey=not_a_hex_or_base64_key"], { logger });

    assert.equal(warnFields.length, 1);
    assert.equal((warnFields[0] as { record?: string }).record, undefined);
    assert.equal(typeof (warnFields[0] as { recordBytes?: number }).recordBytes, "number");
  });
});
