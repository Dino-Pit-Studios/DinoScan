/**
 * DinoScan Reporter
 *
 * Handles report generation and display in various formats
 * including webview panels and output channels.
 */

import {
  ExtensionContext,
  OutputChannel,
  WebviewPanel,
  window,
  ViewColumn,
  Uri,
} from "vscode";
import { join } from "path";

/**
 * DinoscanReporter class.
 *
 * Responsible for generating and displaying DinoScan analysis reports
 * in webview panels and output channels.
 */
export class DinoscanReporter {
  private readonly context: ExtensionContext;
  private readonly outputChannel: OutputChannel;
  private reportPanel: WebviewPanel | undefined;

  /**
   * Creates a new instance of DinoscanReporter.
   * @param context ExtensionContext from the VSCode extension.
   */
  constructor(context: ExtensionContext) {
    this.context = context;
    this.outputChannel = window.createOutputChannel("DinoScan");
  }

  /**
   * Show analysis report in a webview panel
   */
  public async showReport(): Promise<void> {
    if (this.reportPanel) {
      this.reportPanel.reveal();
      return;
    }

    this.reportPanel = window.createWebviewPanel(
      "dinoscanReport",
      "DinoScan Analysis Report",
      ViewColumn.Two,
      {
        enableScripts: true,
        localResourceRoots: [
          Uri.file(join(this.context.extensionPath, "media")),
        ],
      },
    );

    this.reportPanel.onDidDispose(() => {
      this.reportPanel = undefined;
    });

    await this.updateReportContent();
  }

  /**
   * Update the report content with current diagnostics
   */
  private async updateReportContent(): Promise<void> {
    if (!this.reportPanel) {
      return;
    }

    const diagnostics = await this.collectAllDiagnostics();
    const html = this.generateReportHTML(diagnostics);
    this.reportPanel.webview.html = html;
  }

  /**
   * Collect all DinoScan diagnostics from all open documents
   */
  private static async collectAllDiagnostics(): Promise<DiagnosticInfo[]> {
    const diagnostics: DiagnosticInfo[] = [];

    // Get all diagnostics from the collection
    vscode.languages
      .getDiagnostics()
      .forEach(
        ([uri, fileDiagnostics]: [
          vscode.Uri,
          readonly vscode.Diagnostic[],
        ]) => {
          fileDiagnostics
            .filter((d: vscode.Diagnostic) => d.source === "DinoScan")
            .forEach((diagnostic: vscode.Diagnostic) => {
              diagnostics.push({
                file: uri.fsPath,
                line: diagnostic.range.start.line + 1,
                column: diagnostic.range.start.character + 1,
                message: diagnostic.message,
                severity: DinoscanReporter.mapSeverityToString(
                  diagnostic.severity,
                ),
                code: DinoscanReporter.normalizeDiagnosticCode(diagnostic.code),
              });
            });
        },
      );

    return diagnostics.sort((a, b) => {
      // Sort by severity, then by file
      const severityOrder = {
        error: 0,
        warning: 1,
        information: 2,
        hint: 3,
      } as const;
      const aKey = DinoscanReporter.toSeverityKey(a.severity);
      const bKey = DinoscanReporter.toSeverityKey(b.severity);
      const severityDiff = severityOrder[aKey] - severityOrder[bKey];
      if (severityDiff !== 0) {
        return severityDiff;
      }

      return a.file.localeCompare(b.file);
    });
  }

  /**
   * Generate HTML content for the report
   */
  // eslint-disable-next-line max-lines-per-function
  private static generateReportHTML(diagnostics: DiagnosticInfo[]): string {
    const totalFindings = diagnostics.length;
    const severityCounts = DinoscanReporter.getSeverityCounts(diagnostics);

    return `
          <!DOCTYPE html>
          <html lang="en">
          <head>
              <meta charset="UTF-8">
              <meta name="viewport" content="width=device-width, initial-scale=1.0">
              <title>DinoScan Analysis Report</title>
              <style>
                  body {
                      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                      margin: 20px;
                      background-color: var(--vscode-editor-background);
                      color: var(--vscode-editor-foreground);
                  }
                  .header {
                      border-bottom: 1px solid var(--vscode-panel-border);
                      padding-bottom: 20px;
                      margin-bottom: 20px;
                  }
                  .logo {
                      font-size: 24px;
                      font-weight: bold;
                      color: var(--vscode-textLink-foreground);
                      margin-bottom: 10px;
                  }
                  .summary {
                      display: flex;
                      gap: 20px;
                      margin: 20px 0;
                  }
                  .summary-item {
                      background: var(--vscode-button-secondaryBackground);
                      padding: 15px;
                      border-radius: 5px;
                      text-align: center;
                      flex: 1;
                  }
                  .summary-number {
                      font-size: 24px;
                      font-weight: bold;
                      margin-bottom: 5px;
                  }
                  .error { color: var(--vscode-errorForeground); }
                  .warning { color: var(--vscode-list-warningForeground); }
                  .info { color: var(--vscode-list-highlightForeground); }
                  .findings-list {
                      margin-top: 20px;
                }
                .finding-item {
                    background: var(--vscode-editor-background);
                    border: 1px solid var(--vscode-panel-border);
                    border-radius: 5px;
                    padding: 15px;
                    margin-bottom: 10px;
                }
                .finding-header {
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                    margin-bottom: 10px;
                }
                .finding-file {
                    font-weight: bold;
                    color: var(--vscode-textLink-foreground);
                }
                .finding-location {
                    font-size: 12px;
                    color: var(--vscode-descriptionForeground);
                }
                .finding-severity {
                    padding: 2px 8px;
                    border-radius: 3px;
                    font-size: 12px;
                    font-weight: bold;
                }
                .severity-error {
                    background-color: var(--vscode-inputValidation-errorBackground);
                    color: var(--vscode-inputValidation-errorForeground);
                }
                .severity-warning {
                    background-color: var(--vscode-inputValidation-warningBackground);
                    color: var(--vscode-inputValidation-warningForeground);
                }
                .severity-info {
                    background-color: var(--vscode-inputValidation-infoBackground);
                    color: var(--vscode-inputValidation-infoForeground);
                }
                .no-findings {
                    text-align: center;
                    padding: 40px;
                    color: var(--vscode-descriptionForeground);
                }
                .no-findings-icon {
                    font-size: 48px;
                    margin-bottom: 20px;
                }
            </style>
        </head>
        <body>
            <div class="header">
                <div class="logo">🦕 DinoScan Analysis Report</div>
                <div>Generated on ${new Date().toLocaleString()}</div>
            </div>

            <div class="summary">
                <div class="summary-item">
                    <div class="summary-number">${totalFindings}</div>
                    <div>Total Findings</div>
                </div>
                <div class="summary-item error">
          <div class="summary-number">${severityCounts.error}</div>
                    <div>Errors</div>
                </div>
                <div class="summary-item warning">
          <div class="summary-number">${severityCounts.warning}</div>
                    <div>Warnings</div>
                </div>
                <div class="summary-item info">
          <div class="summary-number">${
            severityCounts.information + severityCounts.hint
          }</div>
                    <div>Info/Hints</div>
                </div>
            </div>

            ${
              totalFindings === 0
                ? `
                <div class="no-findings">
                    <div class="no-findings-icon">✅</div>
                    <h3>No Issues Found!</h3>
                    <p>Your code looks clean. Great job!</p>
                </div>
            `
                : `
                <div class="findings-list">
                    <h3>Findings (${totalFindings})</h3>
                    ${diagnostics
                      .map(
                        (finding) => `<div class="finding-item">
                            <div class="finding-header">
                                <div>
                                    <div class="finding-file">${DinoscanReporter.escapeHtml(
                                      path.basename(finding.file),
                                    )}</div>
                                    <div class="finding-location">Line ${
                                      finding.line
                                    }, Column ${finding.column}</div>
                                </div>
                                <div class="finding-severity severity-${DinoscanReporter.getSeverityClass(
                                  finding.severity,
                                )}">${DinoscanReporter.escapeHtml(
                                  finding.severity,
                                )}</div>
                            </div>
                            <div class="finding-message">${DinoscanReporter.escapeHtml(
                              finding.message,
                            )}</div>
                            <div class="finding-code">Rule: ${DinoscanReporter.escapeHtml(
                              finding.code,
                            )}</div>
                        </div>
                        `,
                      )
                      .join("")}
                </div>
            `
            }
        </body>
        </html>
        `;
  }
  /**
   * Escape HTML special characters to prevent injection in the webview
   */
  private static escapeHtml(input: string): string {
    return input
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }

  /**
   * Map severity string to CSS class suffix used in the template
   */
  private static getSeverityClass(severity: string): string {
    switch (severity) {
      case "Error":
        return "error";
      case "Warning":
        return "warning";
      case "Information":
      case "Hint":
        return "info";
      default:
        return "info";
    }
  }

  /**
   * Get counts of findings by severity
   */
  private static getSeverityCounts(
    diagnostics: DiagnosticInfo[],
  ): Record<string, number> {
    const counts: Record<string, number> = {
      error: 0,
      warning: 0,
      information: 0,
      hint: 0,
    };

    diagnostics.forEach((diagnostic) => {
      counts[DinoscanReporter.toSeverityKey(diagnostic.severity)]++;
    });

    return counts;
  }

  /**
   * Converts a severity string to a corresponding severity key.
   * @param severity - The severity string ("Error", "Warning", "Information", or "Hint").
   * @returns The lowercase severity key ("error", "warning", "information", or "hint").
   */
  private static toSeverityKey(
    severity: string,
  ): "error" | "warning" | "information" | "hint" {
    switch (severity) {
      case "Error":
        return "error";
      case "Warning":
        return "warning";
      case "Information":
        return "information";
      case "Hint":
        return "hint";
      default:
        return "information";
    }
  }

  /**
   * Map VS Code diagnostic severity to string
   */
  private static mapSeverityToString(
    severity: vscode.DiagnosticSeverity,
  ): string {
    switch (severity) {
      case vscode.DiagnosticSeverity.Error:
        return "Error";
      case vscode.DiagnosticSeverity.Warning:
        return "Warning";
      case vscode.DiagnosticSeverity.Information:
        return "Information";
      case vscode.DiagnosticSeverity.Hint:
        return "Hint";
      default:
        return "Unknown";
    }
  }

  /**
   * Log message to output channel
   */
  public log(message: string): void {
    this.outputChannel.appendLine(
      `[${new Date().toLocaleTimeString()}] ${message}`,
    );
  }

  /**
   * Normalize diagnostic code to string safely
   */
  private static normalizeDiagnosticCode(
    code: vscode.Diagnostic["code"],
  ): string {
    if (code === undefined || code === null) {
      return "Unknown";
    }
    if (typeof code === "string" || typeof code === "number") {
      return String(code);
    }
    // VS Code DiagnosticCode can be an object with a 'value' property
    const anyCode = code as unknown as { value?: string | number };
    if (anyCode?.value !== undefined) {
      return String(anyCode.value);
    }
    try {
      return JSON.stringify(code);
    } catch {
      return "Unknown";
    }
  }

  /**
   * Show output channel
   */
  public showOutput(): void {
    this.outputChannel.show();
  }

  /**
   * Clear output channel
   */
  public clearOutput(): void {
    this.outputChannel.clear();
  }

  /**
   * Dispose of resources
   */
  public dispose(): void {
    this.outputChannel.dispose();
    if (this.reportPanel) {
      this.reportPanel.dispose();
    }
  }
}

interface DiagnosticInfo {
  file: string;
  line: number;
  column: number;
  message: string;
  severity: string;
  code: string;
}
