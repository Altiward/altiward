// Writes THIRD_PARTY_NOTICES.md: the licence of every third-party component shipped in the
// server image. That is the Go modules linked into altiward-api (plus the Go standard
// library) and the console's production npm packages. The Mac agent ships no third-party
// code; it uses only Apple's system frameworks.
//
//   node scripts/third-party-notices.mjs           write the file
//   node scripts/third-party-notices.mjs --check   fail if the file is out of date
//
// It also refuses to run when a shipped component's licence isn't on ALLOWED_LICENSES, listing
// each offender (name, version, licence) on stderr and exiting 1, in both modes.
//
// Needs Go and an installed console (npm --prefix console ci). Run from the repo root.
import { execFileSync } from "node:child_process";
import { existsSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";

const OUT = "THIRD_PARTY_NOTICES.md";
const LICENSE_FILE = /^(licen[cs]e|copying)(\.(md|txt))?$/i;

// The licences a shipped dependency may use (SPDX identifiers, compared case-insensitively).
// Anything else, including copyleft (GPL, LGPL, AGPL, MPL, SSPL, BUSL) and any licence this
// script can't identify, fails the run. Changing this list is a policy decision, not a fix.
// CC-BY-4.0 is for data packages only (caniuse-lite, say), never for code; this script doesn't
// tell the two apart, so check by hand if it ever turns up.
export const ALLOWED_LICENSES = [
  "MIT", "MIT-0", "BSD-2-Clause", "BSD-3-Clause", "Apache-2.0", "ISC",
  "OFL-1.1", "CC-BY-4.0", "0BSD", "Unlicense",
];
const ALLOWED = new Set(ALLOWED_LICENSES.map((id) => id.toLowerCase()));

// Names the licence in a licence file's text, as an SPDX expression. Copyleft is looked for
// first so it is never hidden behind a permissive notice. Several licences in one file are
// joined with AND (all must be allowed); unrecognised text gives "UNKNOWN", which fails.
function detectLicense(text) {
  const t = text.replace(/\s+/g, " ");
  const copyleft = [
    [/GNU AFFERO GENERAL PUBLIC LICENSE/i, "AGPL-3.0"],
    [/GNU LESSER GENERAL PUBLIC LICENSE/i, "LGPL-3.0"],
    [/GNU (LIBRARY )?GENERAL PUBLIC LICENSE/i, "GPL-3.0"],
    [/Mozilla Public License/i, "MPL-2.0"],
    [/Server Side Public License/i, "SSPL-1.0"],
    [/Business Source License/i, "BUSL-1.1"],
  ].filter(([re]) => re.test(t)).map(([, id]) => id);
  if (copyleft.length) return copyleft.join(" AND ");

  const found = [];
  if (/Apache License,? Version 2\.0/i.test(t)) found.push("Apache-2.0");
  if (/Permission is hereby granted, free of charge/i.test(t)) {
    found.push(/The above copyright notice and this permission notice shall be included/i.test(t) ? "MIT" : "MIT-0");
  }
  if (/Redistribution and use in source and binary forms/i.test(t)) {
    found.push(/Neither the name of/i.test(t) ? "BSD-3-Clause" : "BSD-2-Clause");
  }
  if (/Permission to use, copy, modify, and\/or distribute this software for any purpose with or without fee/i.test(t)) {
    found.push(/provided that the above copyright notice/i.test(t) ? "ISC" : "0BSD");
  }
  if (/free and unencumbered software released into the public domain/i.test(t)) found.push("Unlicense");
  if (/SIL OPEN FONT LICENSE Version 1\.1/i.test(t)) found.push("OFL-1.1");
  if (/Creative Commons Attribution 4\.0/i.test(t)) found.push("CC-BY-4.0");
  return found.length ? found.join(" AND ") : "UNKNOWN";
}

// Whether an SPDX expression is allowed: "A OR B" needs any one alternative, "A AND B" needs
// every one (AND binds tighter than OR; parentheses group). "X WITH exception" is a single
// id, which isn't on the list, so it fails. Malformed expressions fail.
function licenseAllowed(expression) {
  const tokens = expression.match(/\(|\)|[^\s()]+(?:\s+WITH\s+[^\s()]+)?/gi) ?? [];
  let pos = 0;
  const peek = () => tokens[pos];
  function parseOr() {
    let ok = parseAnd();
    while (peek()?.toUpperCase() === "OR") { pos++; const rhs = parseAnd(); ok = ok || rhs; }
    return ok;
  }
  function parseAnd() {
    let ok = parseAtom();
    while (peek()?.toUpperCase() === "AND") { pos++; const rhs = parseAtom(); ok = ok && rhs; }
    return ok;
  }
  function parseAtom() {
    const tok = tokens[pos++];
    if (tok === "(") {
      const ok = parseOr();
      if (tokens[pos++] !== ")") throw new SyntaxError("missing )");
      return ok;
    }
    if (tok === undefined || tok === ")" || /^(AND|OR)$/i.test(tok)) throw new SyntaxError("unexpected token");
    return ALLOWED.has(tok.toLowerCase());
  }
  try {
    const ok = parseOr();
    return ok && pos === tokens.length;
  } catch {
    return false;
  }
}

// The licence npm records for a package: an SPDX string, or an older { type } / [{ type }] form.
function declaredLicense(value) {
  if (typeof value === "string") return value.trim() || null;
  if (Array.isArray(value)) {
    const types = value.map(declaredLicense);
    return types.length && types.every(Boolean) ? types.join(" OR ") : null;
  }
  if (value && typeof value.type === "string") return value.type.trim() || null;
  return null;
}

function licenseIn(dir) {
  const name = readdirSync(dir).filter((f) => LICENSE_FILE.test(f)).sort()[0];
  if (!name) throw new Error(`no licence file in ${dir}`);
  return readFileSync(join(dir, name), "utf8").replace(/\r\n/g, "\n").trim();
}

// The licence text and its SPDX expression for a package directory: the declared one when the
// package manager records it, otherwise whatever the licence file's text says.
function licenseOf(dir, declared = null) {
  const text = licenseIn(dir);
  return { text, license: declared ?? detectLicense(text) };
}

function goModules() {
  const go = (...args) => execFileSync("go", args, { encoding: "utf8" });
  const listed = go("list", "-deps", "-f", "{{with .Module}}{{.Path}} {{.Version}} {{.Dir}}{{end}}",
    "./backend/cmd/altiward-api");
  const modules = new Map();
  for (const line of listed.split("\n")) {
    const [path, version, dir] = line.split(" ");
    // Altiward's own modules (the server and integrations/) are first-party, not third-party.
    if (path && version && path !== "github.com/Altiward/altiward" && !path.startsWith("github.com/Altiward/altiward/")) modules.set(path, { name: path, version, ...licenseOf(dir) });
  }
  // Homebrew keeps the licence one level above GOROOT; the official distribution in it.
  const root = go("env", "GOROOT").trim();
  const goLicense = [root, dirname(root)].find((d) => existsSync(join(d, "LICENSE")));
  if (!goLicense) throw new Error(`no LICENSE in ${root} or its parent`);
  return [
    { name: "Go standard library", version: "", ...licenseOf(goLicense) },
    ...[...modules.values()].sort((a, b) => a.name.localeCompare(b.name)),
  ];
}

function consolePackages() {
  const lock = JSON.parse(readFileSync("console/package-lock.json", "utf8"));
  return Object.entries(lock.packages)
    .filter(([path, p]) => path.startsWith("node_modules/") && !p.dev)
    .map(([path, p]) => ({
      name: path.slice("node_modules/".length),
      version: p.version,
      ...licenseOf(join("console", path), declaredLicense(p.license)),
    }))
    .sort((a, b) => a.name.localeCompare(b.name));
}

function section(title, components) {
  const lines = [`## ${title}`, ""];
  for (const c of components) {
    lines.push(`### ${c.name}${c.version ? ` ${c.version}` : ""}`, "", "```", c.text, "```", "");
  }
  return lines.join("\n");
}

const server = goModules();
const webConsole = consolePackages();
const refused = [...server, ...webConsole].filter((c) => !licenseAllowed(c.license));
if (refused.length) {
  console.error(`Dependencies with a licence that isn't on the allowlist (${ALLOWED_LICENSES.join(", ")}):`);
  for (const c of refused) console.error(`  ${c.name}${c.version ? ` ${c.version}` : ""}: ${c.license}`);
  process.exit(1);
}

const body = [
  "# Third-party notices",
  "",
  "Altiward is licensed under the Apache License 2.0 (see LICENSE). It includes the open-source components",
  "below, each under its own licence. The Mac agent includes none: it uses only Apple's",
  "system frameworks.",
  "",
  "This file is generated by `make notices`; don't edit it by hand.",
  "",
  section("Server (altiward-api)", server),
  section("Console", webConsole),
].join("\n").trimEnd() + "\n";

if (process.argv.includes("--check")) {
  const current = existsSync(OUT) ? readFileSync(OUT, "utf8") : "";
  if (current !== body) {
    console.error(`${OUT} is out of date: run make notices and commit the result.`);
    process.exit(1);
  }
  console.log(`${OUT} is up to date.`);
} else {
  writeFileSync(OUT, body);
  console.log(`Wrote ${OUT}.`);
}
