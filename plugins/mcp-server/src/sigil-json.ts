/**
 * The JSON document `sigil --format json` printed.
 *
 * A current binary prints nothing else on stdout. Older ones (1.3.7 and
 * earlier) let pip print its progress there first (`Looking in indexes: ...`,
 * `Collecting ...`, `Downloading ...`), so when the whole text is not JSON
 * the document is taken to start at a line that begins with `{` and run to
 * the end, as the Rust MCP server reads it.
 */
export function parseSigilJson(stdout: string): any {
  try {
    return JSON.parse(stdout);
  } catch (whole) {
    let at = stdout.indexOf("\n{");
    while (at !== -1) {
      try {
        return JSON.parse(stdout.slice(at + 1));
      } catch {
        // not the start of the document: try the next line that opens an object
      }
      at = stdout.indexOf("\n{", at + 1);
    }
    throw whole;
  }
}
