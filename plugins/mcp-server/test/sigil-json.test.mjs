// Run with `npm test` (builds first). Data: strings written in this file,
// shaped like what `sigil --format json pip ...` printed before 1.3.8 (pip's
// progress, then the report) and after it (the report only).
import test from "node:test";
import assert from "node:assert/strict";
import { parseSigilJson } from "../dist/sigil-json.js";

const report = { package: "wheelok==1.5", summary: { verdict: "LOW RISK" } };

test("a report alone parses", () => {
  assert.deepEqual(parseSigilJson(JSON.stringify(report, null, 2)), report);
});

test("pip's progress in front of the report is skipped", () => {
  const progress =
    "Looking in indexes: https://pypi.org/simple\n" +
    "Collecting wheelok==1.5\n" +
    "  Downloading wheelok-1.5-py3-none-any.whl (10 kB)\n" +
    "Saved ./wheelok-1.5-py3-none-any.whl\n";
  assert.deepEqual(
    parseSigilJson(progress + JSON.stringify(report, null, 2) + "\n"),
    report
  );
});

test("a progress line that opens a brace is not taken for the report", () => {
  const out =
    "{not json\n" + JSON.stringify(report, null, 2) + "\n";
  assert.deepEqual(parseSigilJson(out), report);
});

test("output with no report in it still fails", () => {
  assert.throws(() => parseSigilJson("Collecting x\nDownloading x\n"));
  assert.throws(() => parseSigilJson(""));
});
