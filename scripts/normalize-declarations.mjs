import { readdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const distDir = fileURLToPath(new URL("../dist/", import.meta.url));
const relativeTsImport = /(from\s+["']\.{1,2}\/[^"']+)\.ts(["'])/g;

async function normalizeDeclarations(directory) {
  const entries = await readdir(directory, { withFileTypes: true });

  await Promise.all(
    entries.map(async (entry) => {
      const path = join(directory, entry.name);

      if (entry.isDirectory()) {
        await normalizeDeclarations(path);
        return;
      }

      if (!entry.name.endsWith(".d.ts")) {
        return;
      }

      const current = await readFile(path, "utf8");
      const next = current.replaceAll(relativeTsImport, "$1.js$2");

      if (next !== current) {
        await writeFile(path, next);
      }
    }),
  );
}

await normalizeDeclarations(distDir);
