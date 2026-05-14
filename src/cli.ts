#!/usr/bin/env node
import { discoverPosemesh } from "./discover.ts";
import { demoManifestFetcher, demoNames, demoTxtRecords } from "./demo.ts";
import { DnsResolver, MockResolver } from "./resolvers.ts";
import type { DiscoverPosemeshOptions } from "./types.ts";

interface CliOptions {
  live: boolean;
  dnsServer?: string;
  fetchManifest: boolean;
  requireManifest: boolean;
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

  if (options.requireManifest && !options.live) {
    throw new Error(
      "--require-manifest is for live or verified manifest fetching. Add --live or omit --require-manifest when using mock demo records.",
    );
  }

  const discoveryOptions: DiscoverPosemeshOptions = {
    resolver: options.live ? new DnsResolver(options.dnsServer) : new MockResolver(demoTxtRecords),
    fetchManifest: options.fetchManifest,
    requireManifest: options.requireManifest,
  };

  if (!options.live) {
    discoveryOptions.manifestFetcher = demoManifestFetcher;
    discoveryOptions.manifestFetchOptions = { securityMode: "demo" };
  }

  const result = await discoverPosemesh(name, discoveryOptions);

  console.log(JSON.stringify(result, null, 2));
}

async function runDemo(args: string[]): Promise<void> {
  const { options } = parseArgs(args);
  const results = [];

  if (options.requireManifest) {
    throw new Error("--require-manifest is not supported by npm run demo because demo manifests are unsigned mock data.");
  }

  for (const name of demoNames) {
    results.push(await discoverPosemesh(name, {
      resolver: new MockResolver(demoTxtRecords),
      fetchManifest: options.fetchManifest,
      manifestFetchOptions: { securityMode: "demo" },
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
    requireManifest: false,
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
    } else if (arg === "--require-manifest") {
      options.requireManifest = true;
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
  --require-manifest             Live mode only: fail unless a verified manifest is accepted.

Only subnames under .posemesh are accepted.
`);
}
