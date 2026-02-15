import * as vscode from "vscode";
import { SigilRunner } from "./runner";
import { FindingsProvider, FindingItem } from "./findings";
import { QuarantineProvider } from "./quarantine";

let diagnosticCollection: vscode.DiagnosticCollection;
let findingsProvider: FindingsProvider;
let quarantineProvider: QuarantineProvider;
let runner: SigilRunner;

export function activate(context: vscode.ExtensionContext) {
  diagnosticCollection =
    vscode.languages.createDiagnosticCollection("sigil");
  runner = new SigilRunner();
  findingsProvider = new FindingsProvider();
  quarantineProvider = new QuarantineProvider(runner);

  // Tree views
  vscode.window.registerTreeDataProvider("sigil.findings", findingsProvider);
  vscode.window.registerTreeDataProvider(
    "sigil.quarantine",
    quarantineProvider
  );

  // Commands
  context.subscriptions.push(
    vscode.commands.registerCommand("sigil.scanWorkspace", () =>
      scanWorkspace()
    ),
    vscode.commands.registerCommand("sigil.scanFile", (uri?: vscode.Uri) =>
      scanFile(uri)
    ),
    vscode.commands.registerCommand("sigil.scanSelection", () =>
      scanSelection()
    ),
    vscode.commands.registerCommand("sigil.scanPackage", () => scanPackage()),
    vscode.commands.registerCommand("sigil.showQuarantine", () =>
      quarantineProvider.refresh()
    ),
    vscode.commands.registerCommand("sigil.clearCache", () => clearCache()),
    vscode.commands.registerCommand(
      "sigil.openFinding",
      (finding: FindingItem) => openFinding(finding)
    ),
    diagnosticCollection
  );

  // Auto-scan on save
  context.subscriptions.push(
    vscode.workspace.onDidSaveTextDocument((doc) => {
      const config = vscode.workspace.getConfiguration("sigil");
      if (config.get<boolean>("autoScanOnSave")) {
        scanFile(doc.uri);
      }
    })
  );

  // Status bar
  const statusBar = vscode.window.createStatusBarItem(
    vscode.StatusBarAlignment.Left,
    100
  );
  statusBar.text = "$(shield) Sigil";
  statusBar.command = "sigil.scanWorkspace";
  statusBar.tooltip = "Run Sigil security scan";
  statusBar.show();
  context.subscriptions.push(statusBar);
}

async function scanWorkspace() {
  const folders = vscode.workspace.workspaceFolders;
  if (!folders || folders.length === 0) {
    vscode.window.showWarningMessage("No workspace folder open.");
    return;
  }

  const targetPath = folders[0].uri.fsPath;

  await vscode.window.withProgress(
    {
      location: vscode.ProgressLocation.Notification,
      title: "Sigil: Scanning workspace...",
      cancellable: true,
    },
    async (progress, token) => {
      try {
        const result = await runner.scan(targetPath, token);
        applyDiagnostics(result.findings, targetPath);
        findingsProvider.update(result.findings);
        showVerdictMessage(result);
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        vscode.window.showErrorMessage(`Sigil scan failed: ${msg}`);
      }
    }
  );
}

async function scanFile(uri?: vscode.Uri) {
  const target =
    uri?.fsPath ?? vscode.window.activeTextEditor?.document.uri.fsPath;
  if (!target) {
    vscode.window.showWarningMessage("No file selected.");
    return;
  }

  await vscode.window.withProgress(
    {
      location: vscode.ProgressLocation.Notification,
      title: `Sigil: Scanning ${target.split("/").pop()}...`,
      cancellable: true,
    },
    async (progress, token) => {
      try {
        const result = await runner.scan(target, token);
        applyDiagnostics(result.findings, target);
        findingsProvider.update(result.findings);
        showVerdictMessage(result);
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        vscode.window.showErrorMessage(`Sigil scan failed: ${msg}`);
      }
    }
  );
}

async function scanSelection() {
  const editor = vscode.window.activeTextEditor;
  if (!editor || editor.selection.isEmpty) {
    vscode.window.showWarningMessage("No text selected.");
    return;
  }

  const text = editor.document.getText(editor.selection);
  try {
    const result = await runner.scanSnippet(text);
    findingsProvider.update(result.findings);
    showVerdictMessage(result);
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    vscode.window.showErrorMessage(`Sigil scan failed: ${msg}`);
  }
}

async function scanPackage() {
  const pkgType = await vscode.window.showQuickPick(["npm", "pip"], {
    placeHolder: "Select package manager",
  });
  if (!pkgType) {
    return;
  }

  const pkgName = await vscode.window.showInputBox({
    prompt: `Enter ${pkgType} package name`,
    placeHolder: "e.g. lodash or requests",
  });
  if (!pkgName) {
    return;
  }

  await vscode.window.withProgress(
    {
      location: vscode.ProgressLocation.Notification,
      title: `Sigil: Scanning ${pkgType} package "${pkgName}"...`,
      cancellable: true,
    },
    async (progress, token) => {
      try {
        const result = await runner.scanPackage(pkgType!, pkgName!, token);
        findingsProvider.update(result.findings);
        showVerdictMessage(result);
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        vscode.window.showErrorMessage(`Sigil scan failed: ${msg}`);
      }
    }
  );
}

async function clearCache() {
  try {
    await runner.clearCache();
    vscode.window.showInformationMessage("Sigil: Scan cache cleared.");
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    vscode.window.showErrorMessage(`Sigil: Failed to clear cache: ${msg}`);
  }
}

function openFinding(finding: FindingItem) {
  if (!finding.filePath) {
    return;
  }
  const uri = vscode.Uri.file(finding.filePath);
  const line = finding.line ? finding.line - 1 : 0;
  vscode.window.showTextDocument(uri, {
    selection: new vscode.Range(line, 0, line, 0),
  });
}

// ── Diagnostics ────────────────────────────────────────────────────────────

interface ScanFinding {
  file: string;
  line?: number;
  severity: string;
  rule: string;
  snippet: string;
  phase: string;
}

interface ScanResult {
  verdict: string;
  score: number;
  files_scanned: number;
  findings: ScanFinding[];
  duration_ms: number;
}

function applyDiagnostics(findings: ScanFinding[], basePath: string) {
  diagnosticCollection.clear();

  const byFile = new Map<string, vscode.Diagnostic[]>();

  for (const f of findings) {
    const filePath = f.file.startsWith("/")
      ? f.file
      : `${basePath}/${f.file}`;
    const line = Math.max(0, (f.line ?? 1) - 1);

    const diagnostic = new vscode.Diagnostic(
      new vscode.Range(line, 0, line, 200),
      `[${f.rule}] ${f.snippet}`,
      mapSeverity(f.severity)
    );
    diagnostic.source = "sigil";
    diagnostic.code = f.rule;

    const existing = byFile.get(filePath) ?? [];
    existing.push(diagnostic);
    byFile.set(filePath, existing);
  }

  for (const [filePath, diagnostics] of byFile) {
    diagnosticCollection.set(vscode.Uri.file(filePath), diagnostics);
  }
}

function mapSeverity(severity: string): vscode.DiagnosticSeverity {
  switch (severity.toLowerCase()) {
    case "critical":
    case "high":
      return vscode.DiagnosticSeverity.Error;
    case "medium":
      return vscode.DiagnosticSeverity.Warning;
    case "low":
      return vscode.DiagnosticSeverity.Information;
    default:
      return vscode.DiagnosticSeverity.Hint;
  }
}

function showVerdictMessage(result: ScanResult) {
  const msg = `Sigil: ${result.verdict} (score: ${result.score}, ${result.findings.length} findings, ${result.files_scanned} files in ${result.duration_ms}ms)`;
  switch (result.verdict.toLowerCase()) {
    case "critical":
    case "high_risk":
      vscode.window.showErrorMessage(msg);
      break;
    case "medium_risk":
      vscode.window.showWarningMessage(msg);
      break;
    default:
      vscode.window.showInformationMessage(msg);
  }
}

export function deactivate() {
  diagnosticCollection?.dispose();
}
