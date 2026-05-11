import { discoverPosemesh, demoManifestFetcher, demoNames, demoTxtRecords, MockResolver } from "../src/index.ts";

const resolver = new MockResolver(demoTxtRecords);

for (const name of demoNames) {
  const result = await discoverPosemesh(name, {
    resolver,
    manifestFetcher: demoManifestFetcher,
  });

  console.log(`${name}:`);
  console.log(JSON.stringify(result, null, 2));
}
