import { discoverPosemesh, DnsResolver } from "../src/index.ts";

const name = process.argv[2] ?? "hq.posemesh";
const dnsServer = process.argv[3];

const result = await discoverPosemesh(name, {
  resolver: new DnsResolver(dnsServer),
});

console.log(JSON.stringify(result, null, 2));
