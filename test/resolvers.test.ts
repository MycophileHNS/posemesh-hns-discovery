import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  CompositeResolver,
  DnsResolver,
  DohResolver,
  DotResolver,
  MockResolver,
} from "../src/resolvers.ts";

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

  it("returns detailed TXT and TLSA statuses", async () => {
    const resolver = new MockResolver(
      {
        "hq.posemesh": ["posemesh:v1; capabilities=domain-discovery"],
      },
      {
        name: "mock-a",
        tlsaRecords: {
          "_443._tcp.manifest.example.test": [
            {
              certUsage: 3,
              selector: 1,
              matchingType: 1,
              data: "abcd",
            },
          ],
        },
      },
    );

    const txt = await resolver.resolveTxtDetailed("hq.posemesh");
    const tlsa = await resolver.resolveTlsaDetailed("manifest.example.test", 443);
    const missing = await resolver.resolveTxtDetailed("missing.posemesh");

    assert.equal(txt.status, "ok");
    assert.equal(txt.resolver, "mock-a");
    assert.equal(tlsa.status, "ok");
    assert.equal(tlsa.name, "_443._tcp.manifest.example.test");
    assert.equal(missing.status, "no-records");
  });
});

describe("DnsResolver", () => {
  it("reports unsupported TLSA lookups on Node versions without resolveTlsa", async () => {
    const resolver = new DnsResolver(undefined, "dns-test");
    const internal = resolver as unknown as {
      resolver: { resolveTlsa?: ((name: string) => Promise<unknown[]>) | undefined };
    };
    internal.resolver.resolveTlsa = undefined;

    const detailed = await resolver.resolveTlsaDetailed("manifest.example.test", 443);

    assert.equal(detailed.status, "lookup-error");
    assert.equal(detailed.code, "RESOLVER_UNSUPPORTED");
    assert.match(detailed.error ?? "", /Node\.js 22\.15 or newer/);
    await assert.rejects(
      () => resolver.resolveTlsa("manifest.example.test", 443),
      /Node\.js 22\.15 or newer/,
    );
  });
});

describe("CompositeResolver", () => {
  it("uses first-success strategy by default", async () => {
    const resolver = new CompositeResolver([
      new MockResolver({}, { name: "empty" }),
      new MockResolver(
        { "hq.posemesh": ["posemesh:v1; capabilities=relay-discovery"] },
        { name: "filled" },
      ),
    ]);

    const detailed = await resolver.resolveTxtDetailed("hq.posemesh");

    assert.equal(detailed.status, "ok");
    assert.deepEqual(detailed.records, ["posemesh:v1; capabilities=relay-discovery"]);
    assert.deepEqual(
      detailed.attempts?.map((attempt) => attempt.resolver),
      ["empty", "filled"],
    );
  });

  it("returns quorum answers when enough resolvers agree", async () => {
    const matching = ["posemesh:v1; capabilities=relay-discovery"];
    const resolver = new CompositeResolver(
      [
        new MockResolver({ "hq.posemesh": matching }, { name: "one" }),
        new MockResolver({ "hq.posemesh": matching }, { name: "two" }),
        new MockResolver(
          { "hq.posemesh": ["posemesh:v1; capabilities=domain-discovery"] },
          { name: "three" },
        ),
      ],
      { strategy: "quorum" },
    );

    const detailed = await resolver.resolveTxtDetailed("hq.posemesh");

    assert.equal(detailed.status, "ok");
    assert.deepEqual(detailed.records, matching);
  });

  it("reports strict consensus failures when answers differ", async () => {
    const resolver = new CompositeResolver(
      [
        new MockResolver(
          { "hq.posemesh": ["posemesh:v1; capabilities=relay-discovery"] },
          { name: "one" },
        ),
        new MockResolver(
          { "hq.posemesh": ["posemesh:v1; capabilities=domain-discovery"] },
          { name: "two" },
        ),
      ],
      { strategy: "strict-consensus" },
    );

    const detailed = await resolver.resolveTxtDetailed("hq.posemesh");

    assert.equal(detailed.status, "consensus-failed");
    await assert.rejects(() => resolver.resolveTxt("hq.posemesh"), /Strict consensus failed/);
  });

  it("supports TLSA quorum lookups", async () => {
    const record = {
      certUsage: 3,
      selector: 1,
      matchingType: 1,
      data: "abcd",
    };
    const resolver = new CompositeResolver(
      [
        new MockResolver({}, { name: "one", tlsaRecords: { "_443._tcp.host.test": [record] } }),
        new MockResolver({}, { name: "two", tlsaRecords: { "_443._tcp.host.test": [record] } }),
        new MockResolver({}, { name: "three" }),
      ],
      { strategy: "quorum" },
    );

    assert.deepEqual(await resolver.resolveTlsa("host.test", 443), [record]);
  });

  it("treats TLSA RRsets as equal when resolvers return records in different order", async () => {
    const firstRecord = {
      certUsage: 3,
      selector: 1,
      matchingType: 1,
      data: "abcd",
    };
    const secondRecord = {
      certUsage: 3,
      selector: 0,
      matchingType: 1,
      data: "ef01",
    };
    const resolver = new CompositeResolver(
      [
        new MockResolver(
          {},
          { name: "one", tlsaRecords: { "_443._tcp.host.test": [firstRecord, secondRecord] } },
        ),
        new MockResolver(
          {},
          { name: "two", tlsaRecords: { "_443._tcp.host.test": [secondRecord, firstRecord] } },
        ),
      ],
      { strategy: "strict-consensus" },
    );

    const detailed = await resolver.resolveTlsaDetailed("host.test", 443);

    assert.equal(detailed.status, "ok");
    assert.deepEqual(detailed.records, [firstRecord, secondRecord]);
  });
});

describe("DohResolver", () => {
  it("parses DNS-over-HTTPS TXT answers", async () => {
    const resolver = new DohResolver({
      name: "doh-test",
      fetch: async (input) => {
        const url = new URL(input);
        assert.equal(url.searchParams.get("name"), "hq.posemesh");
        assert.equal(url.searchParams.get("type"), "16");

        return {
          ok: true,
          status: 200,
          json: async () => ({
            Status: 0,
            Answer: [{ type: 16, data: "\"posemesh:v1; \" \"capabilities=relay-discovery\"" }],
          }),
        };
      },
    });

    assert.deepEqual(await resolver.resolveTxt("hq.posemesh"), [
      "posemesh:v1; capabilities=relay-discovery",
    ]);
  });

  it("parses DNS-over-HTTPS TLSA answers", async () => {
    const resolver = new DohResolver({
      name: "doh-test",
      fetch: async (input) => {
        const url = new URL(input);
        assert.equal(url.searchParams.get("name"), "_443._tcp.manifest.example.test");
        assert.equal(url.searchParams.get("type"), "52");

        return {
          ok: true,
          status: 200,
          json: async () => ({
            Status: 0,
            Answer: [{ type: 52, data: "3 1 1 abcd" }],
          }),
        };
      },
    });

    assert.deepEqual(await resolver.resolveTlsa("manifest.example.test", 443), [
      {
        certUsage: 3,
        selector: 1,
        matchingType: 1,
        data: "abcd",
      },
    ]);
  });

  it("reports malformed DNS-over-HTTPS TLSA answers as lookup errors", async () => {
    const resolver = new DohResolver({
      name: "doh-test",
      fetch: async () => ({
        ok: true,
        status: 200,
        json: async () => ({
          Status: 0,
          Answer: [{ type: 52, data: "3 1" }],
        }),
      }),
    });

    const detailed = await resolver.resolveTlsaDetailed("manifest.example.test", 443);

    assert.equal(detailed.status, "lookup-error");
    assert.equal(detailed.code, "RESOLVER_LOOKUP_ERROR");
    assert.match(detailed.error ?? "", /TLSA answer parsing failed/);
    await assert.rejects(() => resolver.resolveTlsa("manifest.example.test", 443), /TLSA answer parsing failed/);
  });
});

describe("DotResolver", () => {
  it("is an explicit prototype stub", async () => {
    const resolver = new DotResolver({ server: "dns.example.test" });
    const detailed = await resolver.resolveTxtDetailed("hq.posemesh");

    assert.equal(detailed.status, "lookup-error");
    assert.match(detailed.error ?? "", /stub/);
    await assert.rejects(() => resolver.resolveTxt("hq.posemesh"), /stub/);
  });
});
