#!/usr/bin/env node
import { discoverPosemesh } from "./discover.ts";
import { demoManifestFetcher, demoNames, demoTxtRecords } from "./demo.ts";
import { DnsResolver, MockResolver } from "./resolvers.ts";
import type { DiscoverPosemeshOptions } from "./types.ts";

interface CliOptions {
  live: boolean;
  dnsServer?: string;
  fetchManifest: boolean;
}

const [command = "help", ...args] = process.argv.slice(2);

try {
  if (command === "resolve") {
    await runResolve(args);
  } else if (command === "demo") {
    await runDemo(args);
  } else {
    printHelp();
    process.exitCode = command === "help" || command === "--help" ? 0 : 1;
  }
} catch (error) {
  console.error(error instanceof Error ? error.message : error);
  process.exitCode = 1;
}

async function runResolve(args: string[]): Promise<void> {
  const { positional, options } = parseArgs(args);
  const [name] = positional;

  if (!name) {
    throw new Error("Missing name. Example: npm run resolve -- hq.posemesh");
  }

  const discoveryOptions: DiscoverPosemeshOptions = {
    resolver: options.live ? new DnsResolver(options.dnsServer) : new MockResolver(demoTxtRecords),
    fetchManifest: options.fetchManifest,
  };

  if (!options.live) {
    discoveryOptions.manifestFetcher = demoManifestFetcher;
  }

  const result = await discoverPosemesh(name, discoveryOptions);

  console.log(JSON.stringify(result, null, 2));
}

async function runDemo(args: string[]): Promise<void> {
  const { options } = parseArgs(args);
  const results = [];

  for (const name of demoNames) {
    results.push(await discoverPosemesh(name, {
      resolver: new MockResolver(demoTxtRecords),
      fetchManifest: options.fetchManifest,
      manifestFetcher: demoManifestFetcher,
    }));
  }

  console.log(JSON.stringify(results, null, 2));
}

function parseArgs(args: string[]): { positional: string[]; options: CliOptions } {
  const positional: string[] = [];
  const options: CliOptions = {
    live: false,
    fetchManifest: true,
  };

  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];

    if (!arg) {
      continue;
    }

    if (arg === "--live") {
      options.live = true;
    } else if (arg === "--no-manifest") {
      options.fetchManifest = false;
    } else if (arg === "--dns-server") {
      const value = args[index + 1];

      if (!value) {
        throw new Error("--dns-server requires a value.");
      }

      options.dnsServer = value;
      index += 1;
    } else {
      positional.push(arg);
    }
  }

  return { positional, options };
}

function printHelp(): void {
  console.log(`posemesh-hns-discovery

Commands:
  npm run resolve -- hq.posemesh
  npm run demo

Options:
  --live                         Resolve TXT records with DNS instead of demo records.
  --dns-server 127.0.0.1:5350    Use a specific Handshake-aware DNS server.
  --no-manifest                  Parse TXT records without fetching manifests.

Only subnames under .posemesh are accepted.
`);
}
