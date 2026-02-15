import * as vscode from "vscode";
import { SigilRunner } from "./runner";

interface QuarantineEntry {
  id: string;
  source: string;
  source_type: string;
  status: string;
  scan_score?: number;
}

class QuarantineItem extends vscode.TreeItem {
  constructor(entry: QuarantineEntry) {
    super(entry.source, vscode.TreeItemCollapsibleState.None);

    this.description = `${entry.source_type} — ${entry.status}`;
    this.tooltip = `ID: ${entry.id}\nScore: ${entry.scan_score ?? "N/A"}`;

    switch (entry.status.toLowerCase()) {
      case "pending":
        this.iconPath = new vscode.ThemeIcon("clock");
        break;
      case "approved":
        this.iconPath = new vscode.ThemeIcon(
          "check",
          new vscode.ThemeColor("testing.iconPassed")
        );
        break;
      case "rejected":
        this.iconPath = new vscode.ThemeIcon(
          "x",
          new vscode.ThemeColor("errorForeground")
        );
        break;
    }
  }
}

export class QuarantineProvider
  implements vscode.TreeDataProvider<QuarantineItem>
{
  private _onDidChangeTreeData = new vscode.EventEmitter<
    QuarantineItem | undefined | void
  >();
  readonly onDidChangeTreeData = this._onDidChangeTreeData.event;

  private entries: QuarantineEntry[] = [];

  constructor(private runner: SigilRunner) {}

  refresh() {
    this.load();
  }

  private async load() {
    try {
      const raw = await this.runner.listQuarantine();
      this.entries = JSON.parse(raw);
    } catch {
      this.entries = [];
    }
    this._onDidChangeTreeData.fire();
  }

  getTreeItem(element: QuarantineItem): vscode.TreeItem {
    return element;
  }

  getChildren(): QuarantineItem[] {
    return this.entries.map((e) => new QuarantineItem(e));
  }
}
