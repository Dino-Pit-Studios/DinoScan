import * as path from 'path';
import * as vscode from 'vscode';

interface FindingNodeData {
  uri: vscode.Uri;
  diagnostic: vscode.Diagnostic;
}

type DinoscanTreeNode = FileTreeItem | FindingTreeItem;

export class DinoscanFindingsTreeProvider implements vscode.TreeDataProvider<DinoscanTreeNode> {
  private readonly _onDidChangeTreeData = new vscode.EventEmitter<DinoscanTreeNode | undefined>();
  readonly onDidChangeTreeData = this._onDidChangeTreeData.event;

  constructor(private readonly context: vscode.ExtensionContext) {
    context.subscriptions.push(vscode.languages.onDidChangeDiagnostics(() => this.refresh()));
  }

  refresh(): void {
    this._onDidChangeTreeData.fire(undefined);
  }

  static getTreeItem(element: DinoscanTreeNode): vscode.TreeItem | Thenable<vscode.TreeItem> {
    return element;
  }

  getChildren(element?: DinoscanTreeNode): vscode.ProviderResult<DinoscanTreeNode[]> {
    if (!element) {
      return this.getFilesWithFindings();
    }

    if (element instanceof FileTreeItem) {
      return this.getFindingsForFile(element.uri);
    }

    return [];
  }

  private getFilesWithFindings(): FileTreeItem[] {
    const diagnosticsByFile = this.collectDiagnostics();

    return diagnosticsByFile.map(({ uri, diagnostics }) => {
      const label = `${path.basename(uri.fsPath)} (${diagnostics.length})`;
      return new FileTreeItem(label, uri, diagnostics.length);
    });
  }

  private static getFindingsForFile(uri: vscode.Uri): FindingTreeItem[] {
    const diagnostics = vscode.languages
      .getDiagnostics()
      .find(([entryUri]) => entryUri.toString() === uri.toString())?.[1]
      ?.filter(diagnostic => diagnostic.source === 'DinoScan');

    if (!diagnostics || diagnostics.length === 0) {
      return [];
    }

    return diagnostics.map(diagnostic => new FindingTreeItem(uri, diagnostic));
  }

  private static collectDiagnostics(): Array<{ uri: vscode.Uri; diagnostics: vscode.Diagnostic[] }> {
    const diagnostics: Array<{ uri: vscode.Uri; diagnostics: vscode.Diagnostic[] }> = [];

    vscode.languages.getDiagnostics().forEach(([uri, uriDiagnostics]) => {
      const relevant = uriDiagnostics.filter(diagnostic => diagnostic.source === 'DinoScan');
      if (relevant.length > 0) {
        diagnostics.push({ uri, diagnostics: relevant });
      }
    });

    diagnostics.sort((a, b) => a.uri.fsPath.localeCompare(b.uri.fsPath));
    return diagnostics;
  }
}

class FileTreeItem extends vscode.TreeItem {
  constructor(
    label: string,
    public readonly uri: vscode.Uri,
    private readonly count: number
  ) {
    super(label, vscode.TreeItemCollapsibleState.Collapsed);
    this.contextValue = 'dinoscanFile';
    const workspaceRoot = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath ?? '';
    this.description = path.dirname(path.relative(workspaceRoot, uri.fsPath));
    this.iconPath = new vscode.ThemeIcon('file-code');
    this.tooltip = `${uri.fsPath}\n${countLabel(this.count)}`;
  }
}

class FindingTreeItem extends vscode.TreeItem {
  constructor(
    public readonly uri: vscode.Uri,
    private readonly finding: vscode.Diagnostic
  ) {
    super(finding.message, vscode.TreeItemCollapsibleState.None);
    this.iconPath = severityIcon(finding.severity);
    this.contextValue = 'dinoscanFinding';
    const position = finding.range.start;
    this.description = `Line ${position.line + 1}, Col ${position.character + 1}`;
    this.command = {
      title: 'Open Finding',
      command: 'vscode.open',
      arguments: [
        uri,
        {
          selection: finding.range,
        },
      ],
    };
    this.tooltip = `${finding.message}\nRule: ${finding.code ?? 'Unknown'}`;
  }
}

function severityIcon(severity: vscode.DiagnosticSeverity): vscode.ThemeIcon {
  switch (severity) {
    case vscode.DiagnosticSeverity.Error:
      return new vscode.ThemeIcon('error');
    case vscode.DiagnosticSeverity.Warning:
      return new vscode.ThemeIcon('warning');
    case vscode.DiagnosticSeverity.Information:
      return new vscode.ThemeIcon('info');
    case vscode.DiagnosticSeverity.Hint:
      return new vscode.ThemeIcon('lightbulb');
    default:
      return new vscode.ThemeIcon('question');
  }
}

function countLabel(count: number): string {
  return `${count} finding${count === 1 ? '' : 's'}`;
}
