import { Resolver } from "node:dns/promises";
import type { TxtResolver } from "./types.ts";

const NO_RECORD_CODES = new Set(["ENODATA", "ENOTFOUND", "NOTFOUND"]);

export class MockResolver implements TxtResolver {
  readonly records: Map<string, string[]>;

  constructor(records: Record<string, string[]> | Map<string, string[]>) {
    const entries = records instanceof Map ? records.entries() : Object.entries(records);
    this.records = new Map([...entries].map(([name, values]) => [name.toLowerCase(), values]));
  }

  async resolveTxt(name: string): Promise<string[]> {
    return this.records.get(name.toLowerCase()) ?? [];
  }
}

export class DnsResolver implements TxtResolver {
  private readonly resolver: Resolver;

  constructor(server?: string) {
    this.resolver = new Resolver();

    if (server) {
      this.resolver.setServers([server]);
    }
  }

  async resolveTxt(name: string): Promise<string[]> {
    try {
      const answers = await this.resolver.resolveTxt(name);
      return answers.map((segments) => segments.join(""));
    } catch (error) {
      if (isNoRecordError(error)) {
        return [];
      }

      const message = error instanceof Error ? error.message : "Unknown DNS error.";
      throw new Error(`TXT lookup failed for ${name}: ${message}`, { cause: error });
    }
  }
}

function isNoRecordError(error: unknown): boolean {
  if (!error || typeof error !== "object") {
    return false;
  }

  const code = "code" in error ? String(error.code) : "";
  return NO_RECORD_CODES.has(code);
}
