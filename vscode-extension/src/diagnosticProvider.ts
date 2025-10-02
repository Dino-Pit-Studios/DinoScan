/**
 * DinoScan Diagnostic Provider
 *
 * Converts DinoScan findings into VS Code diagnostics and provides
 * code actions for fixing issues.
 */

import * as vscode from 'vscode';

export interface DinoscanFinding {
  file: string;
  line: number;
  column: number;
  message: string;
  severity: 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  category: string;
  rule_id?: string;
  fix_suggestion?: string;
}

export class DinoscanDiagnosticProvider implements vscode.CodeActionProvider {
  private readonly diagnosticCollection: vscode.DiagnosticCollection;

  constructor() {
    this.diagnosticCollection = vscode.languages.createDiagnosticCollection('dinoscan');
  }

  /**
   * Update diagnostics for a document based on DinoScan findings
   */
  public updateDiagnostics(document: vscode.TextDocument, findings: DinoscanFinding[]): void {
    const diagnostics: vscode.Diagnostic[] = [];

    findings.forEach(finding => {
      const line = Math.max(0, finding.line - 1); // Convert to 0-based
      const column = Math.max(0, finding.column - 1);

      const range = new vscode.Range(
        new vscode.Position(line, column),
        new vscode.Position(line, column + 10) // Approximate range
      );

      const diagnostic = new vscode.Diagnostic(
        range,
        finding.message,
        this.mapSeverity(finding.severity)
      );

      diagnostic.source = 'DinoScan';
      diagnostic.code = finding.rule_id || finding.category;

      if (finding.fix_suggestion) {
        (diagnostic as DinoscanAugmentedDiagnostic).dinoscan = {
          suggestion: finding.fix_suggestion,
        };
      }

      // Add tags for different types of issues
      if (finding.category.toLowerCase().includes('security')) {
        diagnostic.tags = [vscode.DiagnosticTag.Unnecessary];
      } else if (finding.category.toLowerCase().includes('deprecated')) {
        diagnostic.tags = [vscode.DiagnosticTag.Deprecated];
      }

      diagnostics.push(diagnostic);
    });

    this.diagnosticCollection.set(document.uri, diagnostics);
  }

  /**
   * Get diagnostics for a specific document
   */
  public getDiagnostics(uri: vscode.Uri): readonly vscode.Diagnostic[] {
    return this.diagnosticCollection.get(uri) || [];
  }

  /**
   * Get total number of findings across all documents
   */
  public getTotalFindings(): number {
    let total = 0;
    this.diagnosticCollection.forEach(
      (uri: vscode.Uri, diagnostics: readonly vscode.Diagnostic[]) => {
        total += diagnostics.length;
      }
    );
    return total;
  }

  /**
   * Clear all diagnostics
   */
  public clear(): void {
    this.diagnosticCollection.clear();
    vscode.window.showInformationMessage('DinoScan diagnostics cleared');
  }

  /**
   * Clear diagnostics for a specific document
   */
  public clearDocument(document: vscode.TextDocument): void {
    this.diagnosticCollection.delete(document.uri);
  }

  /**
   * Suppress a specific diagnostic instance for the current session
   */
  public suppressDiagnostic(document: vscode.TextDocument, diagnostic: vscode.Diagnostic): void {
    const remaining = Array.from(this.getDiagnostics(document.uri)).filter(
      existing => existing !== diagnostic
    );
    this.diagnosticCollection.set(document.uri, remaining);
  }

  /**
   * Provide code actions for DinoScan diagnostics
   */
  public static provideCodeActions(
    document: vscode.TextDocument,
    range: vscode.Range | vscode.Selection,
    context: vscode.CodeActionContext,
    token: vscode.CancellationToken
  ): vscode.CodeAction[] | undefined {
    const actions: vscode.CodeAction[] = [];

    // Filter for DinoScan diagnostics in the current range
    const dinoscanDiagnostics = context.diagnostics.filter(
      (diagnostic: vscode.Diagnostic) => diagnostic.source === 'DinoScan'
    );

    dinoscanDiagnostics.forEach((diagnostic: vscode.Diagnostic) => {
      // Add "Ignore this issue" action
      const ignoreAction = new vscode.CodeAction(
        `DinoScan: Ignore this ${diagnostic.code}`,
        vscode.CodeActionKind.QuickFix
      );
      ignoreAction.diagnostics = [diagnostic];
      ignoreAction.command = {
        command: 'dinoscan.ignoreIssue',
        title: 'Ignore issue',
        arguments: [document, diagnostic],
      };
      actions.push(ignoreAction);

      // Add "Show documentation" action
      const docAction = new vscode.CodeAction(
        `DinoScan: Learn more about ${diagnostic.code}`,
        vscode.CodeActionKind.QuickFix
      );
      docAction.diagnostics = [diagnostic];
      docAction.command = {
        command: 'dinoscan.showDocumentation',
        title: 'Show documentation',
        arguments: [diagnostic.code],
      };
      actions.push(docAction);

      // Add fix suggestion if available
      if (diagnostic.message.includes('Fix:')) {
        const fixAction = new vscode.CodeAction(
          'DinoScan: Apply suggested fix',
          vscode.CodeActionKind.QuickFix
        );
        fixAction.diagnostics = [diagnostic];
        fixAction.command = {
          command: 'dinoscan.applyFix',
          title: 'Apply fix',
          arguments: [document, diagnostic],
        };
        actions.push(fixAction);
      }
    });

    return actions.length > 0 ? actions : undefined;
  }

  /**
   * Map DinoScan severity to VS Code diagnostic severity
   */
  private static mapSeverity(severity: string): vscode.DiagnosticSeverity {
    switch (severity.toLowerCase()) {
      case 'high':
        return vscode.DiagnosticSeverity.Error;
      case 'medium':
        return vscode.DiagnosticSeverity.Warning;
      case 'low':
        return vscode.DiagnosticSeverity.Information;
      case 'info':
        return vscode.DiagnosticSeverity.Hint;
      default:
        return vscode.DiagnosticSeverity.Warning;
    }
  }

  /**
   * Dispose of the diagnostic collection
   */
  public dispose(): void {
    this.diagnosticCollection.dispose();
  }
}

interface DinoscanAugmentedDiagnostic extends vscode.Diagnostic {
  dinoscan?: {
    suggestion?: string;
  };
}
