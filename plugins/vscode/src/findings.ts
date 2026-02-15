import * as vscode from "vscode";

interface ScanFinding {
  file: string;
  line?: number;
  severity: string;
  rule: string;
  snippet: string;
  phase: string;
}

export class FindingItem extends vscode.TreeItem {
  constructor(
    public readonly finding: ScanFinding,
    public readonly filePath?: string,
    public readonly line?: number
  ) {
    super(
      `[${finding.severity.toUpperCase()}] ${finding.rule}`,
      vscode.TreeItemCollapsibleState.None
    );

    this.description = finding.file + (finding.line ? `:${finding.line}` : "");
    this.tooltip = finding.snippet;
    this.iconPath = FindingItem.severityIcon(finding.severity);

    this.filePath = finding.file;
    this.line = finding.line;

    this.command = {
      command: "sigil.openFinding",
      title: "Open Finding",
      arguments: [this],
    };
  }

  private static severityIcon(
    severity: string
  ): vscode.ThemeIcon {
    switch (severity.toLowerCase()) {
      case "critical":
        return new vscode.ThemeIcon(
          "error",
          new vscode.ThemeColor("errorForeground")
        );
      case "high":
        return new vscode.ThemeIcon(
          "warning",
          new vscode.ThemeColor("errorForeground")
        );
      case "medium":
        return new vscode.ThemeIcon(
          "warning",
          new vscode.ThemeColor("editorWarning.foreground")
        );
      case "low":
        return new vscode.ThemeIcon("info");
      default:
        return new vscode.ThemeIcon("circle-outline");
    }
  }
}

export class FindingsProvider
  implements vscode.TreeDataProvider<FindingItem>
{
  private _onDidChangeTreeData = new vscode.EventEmitter<
    FindingItem | undefined | void
  >();
  readonly onDidChangeTreeData = this._onDidChangeTreeData.event;

  private findings: ScanFinding[] = [];

  update(findings: ScanFinding[]) {
    this.findings = findings;
    this._onDidChangeTreeData.fire();
  }

  getTreeItem(element: FindingItem): vscode.TreeItem {
    return element;
  }

  getChildren(): FindingItem[] {
    return this.findings.map((f) => new FindingItem(f, f.file, f.line));
  }
}
