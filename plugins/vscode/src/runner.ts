import * as vscode from "vscode";
import { execFile } from "child_process";
import { writeFileSync, unlinkSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";

interface ScanFinding {
  file: string;
  line?: number;
  severity: string;
  rule: string;
  snippet: string;
  phase: string;
  weight: number;
}

export interface ScanResult {
  verdict: string;
  score: number;
  files_scanned: number;
  findings: ScanFinding[];
  duration_ms: number;
}

export class SigilRunner {
  private getBinary(): string {
    return vscode.workspace
      .getConfiguration("sigil")
      .get<string>("binaryPath", "sigil");
  }

  private getArgs(): string[] {
    const config = vscode.workspace.getConfiguration("sigil");
    const args: string[] = ["--format", "json"];

    const phases = config.get<string>("phases", "");
    if (phases) {
      args.push("--phases", phases);
    }

    const severity = config.get<string>("severityThreshold", "low");
    if (severity !== "low") {
      args.push("--severity", severity);
    }

    return args;
  }

  async scan(
    path: string,
    token?: vscode.CancellationToken
  ): Promise<ScanResult> {
    const binary = this.getBinary();
    const args = [...this.getArgs(), "scan", path];
    return this.execute(binary, args, token);
  }

  async scanPackage(
    manager: string,
    name: string,
    token?: vscode.CancellationToken
  ): Promise<ScanResult> {
    const binary = this.getBinary();
    const args = [...this.getArgs(), manager, name];
    return this.execute(binary, args, token);
  }

  async scanSnippet(code: string): Promise<ScanResult> {
    const tmpFile = join(tmpdir(), `sigil-snippet-${Date.now()}.txt`);
    writeFileSync(tmpFile, code, "utf-8");
    try {
      const binary = this.getBinary();
      const args = [...this.getArgs(), "scan", tmpFile];
      return await this.execute(binary, args);
    } finally {
      try {
        unlinkSync(tmpFile);
      } catch {
        // ignore cleanup errors
      }
    }
  }

  async clearCache(): Promise<void> {
    const binary = this.getBinary();
    await this.execute(binary, ["clear-cache"]);
  }

  async listQuarantine(): Promise<string> {
    const binary = this.getBinary();
    return new Promise((resolve, reject) => {
      execFile(
        binary,
        ["list", "--format", "json"],
        { timeout: 30_000 },
        (err, stdout, stderr) => {
          if (err) {
            reject(new Error(stderr || err.message));
          } else {
            resolve(stdout);
          }
        }
      );
    });
  }

  private execute(
    binary: string,
    args: string[],
    token?: vscode.CancellationToken
  ): Promise<ScanResult> {
    return new Promise((resolve, reject) => {
      const proc = execFile(
        binary,
        args,
        { timeout: 300_000, maxBuffer: 10 * 1024 * 1024 },
        (err, stdout, stderr) => {
          // sigil returns non-zero exit codes for findings — that's ok
          if (err && !stdout) {
            reject(
              new Error(
                stderr || err.message || "sigil exited with no output"
              )
            );
            return;
          }
          try {
            const result = JSON.parse(stdout);
            resolve(result);
          } catch {
            reject(new Error(`Failed to parse sigil output: ${stdout}`));
          }
        }
      );

      token?.onCancellationRequested(() => {
        proc.kill("SIGTERM");
        reject(new Error("Scan cancelled"));
      });
    });
  }
}
