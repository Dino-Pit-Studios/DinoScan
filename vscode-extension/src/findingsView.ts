import * as path from "path";
import {
  Uri,
  Diagnostic,
  TreeDataProvider,
  EventEmitter,
  languages,
  ExtensionContext,
  TreeItem,
} from "vscode";

interface FindingNodeData {
  uri: Uri;
  diagnostic: Diagnostic;
}

type DinoscanTreeNode = FileTreeItem | FindingTreeItem;

/**
 * Provides a tree view of DinoScan findings grouped by file and individual diagnostics.
 * Implements the vscode.TreeDataProvider interface for DinoscanTreeNode items.
 */
export class DinoscanFindingsTreeProvider
  implements TreeDataProvider<DinoscanTreeNode>
{
  private readonly _onDidChangeTreeData = new EventEmitter<
    DinoscanTreeNode | undefined
  >();
  readonly onDidChangeTreeData = this._onDidChangeTreeData.event;

  /**
   * Initializes a new instance of the DinoscanFindingsTreeProvider.
   * Registers for diagnostics change events to refresh the tree.
   * @param context The extension context used to subscribe to VSCode events.
   */
  constructor(private readonly context: ExtensionContext) {
    context.subscriptions.push(
      languages.onDidChangeDiagnostics(() => this.refresh()),
    );
  }

  /**
   * Refreshes the tree view by firing the tree data change event.
   * @returns void
   */
  refresh(): void {
    this._onDidChangeTreeData.fire(undefined);
  }

  /**
   * Returns a TreeItem representation of the given DinoscanTreeNode.
   * @param element The tree node to convert to a TreeItem.
   * @returns A TreeItem or a promise resolving to a TreeItem.
   */
  static getTreeItem(element: DinoscanTreeNode): TreeItem | Thenable<TreeItem> {
    return element;
  }

  /**
   * Retrieves the children of a given tree node or root items if no element is provided.
   * @param element Optional tree node for which to retrieve children.
   * @returns An array or promise of DinoscanTreeNode items.
   */
  getChildren(
    element?: DinoscanTreeNode,
  ): vscode.ProviderResult<DinoscanTreeNode[]> {
    if (!element) {
      return this.getFilesWithFindings();
    }

    if (element instanceof FileTreeItem) {
      return this.getFindingsForFile(element.uri);
    }

    return [];
  }

  /**
   * Collects diagnostics from all files and creates FileTreeItem instances.
   * @returns An array of FileTreeItem objects representing files with DinoScan findings.
   */
  private getFilesWithFindings(): FileTreeItem[] {
    const diagnosticsByFile = this.collectDiagnostics();

    return diagnosticsByFile.map(({ uri, diagnostics }) => {
      const label = `${path.basename(uri.fsPath)} (${diagnostics.length})`;
      return new FileTreeItem(label, uri, diagnostics.length);
    });
  }

  /**
   * Gets the diagnostic findings for a specific file URI.
   * @param uri The URI of the file for which to retrieve diagnostics.
   * @returns An array of FindingTreeItem objects for the specified file.
   */
  private static getFindingsForFile(uri: vscode.Uri): FindingTreeItem[] {
    const diagnostics = vscode.languages
      .getDiagnostics()
      .find(([entryUri]) => entryUri.toString() === uri.toString())?.[1]
      ?.filter((diagnostic) => diagnostic.source === "DinoScan");

    if (!diagnostics || diagnostics.length === 0) {
      return [];
    }

    return diagnostics.map(
      (diagnostic) => new FindingTreeItem(uri, diagnostic),
    );
  }

  /**
   * Collects and filters diagnostics from all open files for the "DinoScan" source.
   * @returns An array of objects each containing a file URI and its relevant diagnostics.
   */
  private static collectDiagnostics(): Array<{
    uri: vscode.Uri;
    diagnostics: vscode.Diagnostic[];
  }> {
    const diagnostics: Array<{
      uri: vscode.Uri;
      diagnostics: vscode.Diagnostic[];
    }> = [];

    vscode.languages.getDiagnostics().forEach(([uri, uriDiagnostics]) => {
      const relevant = uriDiagnostics.filter(
        (diagnostic) => diagnostic.source === "DinoScan",
      );
      if (relevant.length > 0) {
        diagnostics.push({ uri, diagnostics: relevant });
      }
    });

    diagnostics.sort((a, b) => a.uri.fsPath.localeCompare(b.uri.fsPath));
    return diagnostics;
  }
}

/**
 * Represents a file item in the findings view tree.
 * Extends vscode.TreeItem to display file information such as path and finding count.
 */
class FileTreeItem extends vscode.TreeItem {
  /**
   * Initializes a new instance of FileTreeItem.
   * @param label - The display label for the tree item.
   * @param uri - The URI of the file.
   * @param count - The number of findings associated with the file.
   */
  constructor(
    label: string,
    public readonly uri: vscode.Uri,
    private readonly count: number,
  ) {
    super(label, vscode.TreeItemCollapsibleState.Collapsed);
    this.contextValue = "dinoscanFile";
    const workspaceRoot =
      vscode.workspace.workspaceFolders?.[0]?.uri.fsPath ?? "";
    this.description = path.dirname(path.relative(workspaceRoot, uri.fsPath));
    this.iconPath = new vscode.ThemeIcon("file-code");
    this.tooltip = `${uri.fsPath}\n${countLabel(this.count)}`;
  }
}

/**
 * Represents a tree item for a diagnostic finding in the VSCode TreeView.
 * Displays the finding's message with the appropriate severity icon,
 * provides a description with line and column information, and
 * includes a command to open the file at the finding location.
 */
class FindingTreeItem extends vscode.TreeItem {
  /**
   * Creates a new FindingTreeItem.
   * @param uri - The URI of the file containing the finding.
   * @param finding - The diagnostic information for the finding.
   */
  constructor(
    public readonly uri: vscode.Uri,
    private readonly finding: vscode.Diagnostic,
  ) {
    super(finding.message, vscode.TreeItemCollapsibleState.None);
    this.iconPath = severityIcon(finding.severity);
    this.contextValue = "dinoscanFinding";
    const position = finding.range.start;
    this.description = `Line ${position.line + 1}, Col ${position.character + 1}`;
    this.command = {
      title: "Open Finding",
      command: "vscode.open",
      arguments: [
        uri,
        {
          selection: finding.range,
        },
      ],
    };
    this.tooltip = `${finding.message}\nRule: ${finding.code ?? "Unknown"}`;
  }
}

/**
 * Returns a ThemeIcon corresponding to a given diagnostic severity.
 * @param severity The diagnostic severity level.
 * @returns The ThemeIcon representing the severity.
 */
function severityIcon(severity: vscode.DiagnosticSeverity): vscode.ThemeIcon {
  switch (severity) {
    case vscode.DiagnosticSeverity.Error:
      return new vscode.ThemeIcon("error");
    case vscode.DiagnosticSeverity.Warning:
      return new vscode.ThemeIcon("warning");
    case vscode.DiagnosticSeverity.Information:
      return new vscode.ThemeIcon("info");
    case vscode.DiagnosticSeverity.Hint:
      return new vscode.ThemeIcon("lightbulb");
    default:
      return new vscode.ThemeIcon("question");
  }
}

/**
 * Generates a label for the given number of findings, pluralizing "finding" as needed.
 *
 * @param count - The number of findings.
 * @returns The formatted label string (e.g., "1 finding" or "2 findings").
 */
function countLabel(count: number): string {
  return `${count} finding${count === 1 ? "" : "s"}`;
}
