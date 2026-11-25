#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const rootDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const distCli = path.join(rootDir, "dist", "cli.mjs");
const srcCli = path.join(rootDir, "src", "cli.ts");
const entry = fs.existsSync(distCli) ? distCli : srcCli;

await import(pathToFileURL(entry).href);
