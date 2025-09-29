/**
 * DinoScan VS Code Extension
 *
 * Provides comprehensive AST-based Python code analysis directly in VS Code
 * with real-time diagnostics, security scanning, and code quality metrics.
 */

import { spawn, spawnSync } from "child_process";
import * as fs from "fs";
import * as path from "path";
import { window } from "vscode";
import type { ExtensionContext } from "vscode";
import type { DinoscanFinding } from "./diagnosticProvider";
import { DinoscanDiagnosticProvider } from "./diagnosticProvider";
import { DinoscanFindingsTreeProvider } from "./findingsView";
import { DinoscanReporter } from "./reporter";
import { DinoscanStatusBar } from "./statusBar";

type AnalyzerName =
  | "security"
  | "circular"
  | "dead-code"
  | "docs"
  | "duplicates";

const ALL_ANALYZERS: AnalyzerName[] = [
  "security",
  "circular",
  "dead-code",
  "docs",
  "duplicates",
];
const ANALYZER_SET = new Set<AnalyzerName>(ALL_ANALYZERS);

/**
 * Normalizes the given analyzer name to a valid AnalyzerName.
 * @param name The analyzer name input, possibly undefined or null.
 * @returns The normalized AnalyzerName if valid; otherwise, null.
 */
function normalizeAnalyzerName(
  name: string | undefined | null,
): AnalyzerName | null {
  if (!name) {
    return null;
  }

  const candidate = name.toLowerCase() as AnalyzerName;
  return ANALYZER_SET.has(candidate) ? candidate : null;
}

/**
 * Activates the DinoScan VS Code extension.
 * Initializes diagnostic providers, status bar, reporter, views, and registers commands.
 * @param context The extension context provided by VS Code.
 */
export function activate(context: ExtensionContext) {
  console.log("DinoScan extension is now active!");

  // Initialize providers
  const diagnosticProvider = new DinoscanDiagnosticProvider();
  const statusBar = new DinoscanStatusBar();
  const reporter = new DinoscanReporter(context);
  const output = window.createOutputChannel("DinoScan");
  context.subscriptions.push(output);

  const findingsTreeProvider = new DinoscanFindingsTreeProvider(context);
  const findingsTreeView = window.createTreeView("dinoscanFindingsView", {
    treeDataProvider: findingsTreeProvider,
    showCollapseAll: true,
  });
  context.subscriptions.push(findingsTreeView);

  statusBar.updateVisibility();

  // Register diagnostic provider
  context.subscriptions.push(
    vscode.languages.registerCodeActionsProvider("python", diagnosticProvider, {
      providedCodeActionKinds: [vscode.CodeActionKind.QuickFix],
    }),
  );

  // Register commands
  const commands = [
    vscode.commands.registerCommand("dinoscan.analyzeFile", () =>
      analyzeCurrentFile(diagnosticProvider, statusBar, output),
    ),
    vscode.commands.registerCommand("dinoscan.analyzeWorkspace", () =>
      analyzeWorkspace(diagnosticProvider, statusBar, output),
    ),
    vscode.commands.registerCommand("dinoscan.showReport", () =>
      reporter.showReport(),
    ),
    vscode.commands.registerCommand("dinoscan.clearDiagnostics", () =>
      diagnosticProvider.clear(),
    ),
    vscode.commands.registerCommand("dinoscan.toggleAutoAnalysis", () =>
      toggleAutoAnalysis(),
    ),
    vscode.commands.registerCommand(
      "dinoscan.ignoreIssue",
      (document: vscode.TextDocument, diagnostic: vscode.Diagnostic) => {
        if (!document || !diagnostic) {
          vscode.window.showInformationMessage(
            "No DinoScan diagnostic selected to ignore.",
          );
          return;
        }

        diagnosticProvider.suppressDiagnostic(document, diagnostic);
        vscode.window.showInformationMessage(
          "DinoScan diagnostic ignored for this session.",
        );
      },
    ),
    vscode.commands.registerCommand(
      "dinoscan.showDocumentation",
      (code?: string) => {
        const query = code ? encodeURIComponent(code) : "DinoScan diagnostics";
        const url = vscode.Uri.parse(
          `https://github.com/DinoAir/DinoScan/search?q=${query}`,
        );
        vscode.env.openExternal(url);
      },
    ),
    vscode.commands.registerCommand(
      "dinoscan.applyFix",
      async (document: vscode.TextDocument, diagnostic: vscode.Diagnostic) => {
        if (!document || !diagnostic) {
          vscode.window.showInformationMessage(
            "No DinoScan diagnostic selected for fixing.",
          );
          return;
        }

        const augmented = diagnostic as { dinoscan?: { suggestion?: string } };
        const explicitSuggestion = augmented.dinoscan?.suggestion;
        const inferredSuggestion = extractFixSuggestion(diagnostic.message);
        const suggestion = explicitSuggestion || inferredSuggestion;

        if (!suggestion) {
          vscode.window.showInformationMessage(
            "This DinoScan finding does not include an automatic fix suggestion.",
          );
          return;
        }

        await vscode.env.clipboard.writeText(suggestion);
        vscode.window.showInformationMessage(
          "Suggested fix copied to clipboard. Review and apply it in your file.",
        );
      },
    ),
  ];

  context.subscriptions.push(...commands);

  context.subscriptions.push(
    vscode.workspace.onDidChangeConfiguration((event) => {
      if (event.affectsConfiguration("dinoscan.showStatusBar")) {
        statusBar.updateVisibility();
      }
    }),
  );

  // Auto-analysis on file save
  context.subscriptions.push(
    vscode.workspace.onDidSaveTextDocument((document: vscode.TextDocument) => {
      if (isAutoAnalysisEnabled() && document.languageId === "python") {
        analyzeDocument(document, diagnosticProvider, statusBar, output);
      }
    }),
  );

  // Auto-analysis on file open
  context.subscriptions.push(
    vscode.workspace.onDidOpenTextDocument((document: vscode.TextDocument) => {
      if (isAutoAnalysisEnabled() && document.languageId === "python") {
        analyzeDocument(document, diagnosticProvider, statusBar, output);
      }
    }),
  ); // Show welcome message
  showWelcomeMessage(context);
}

/**
 * Called when the DinoScan extension is deactivated.
 *
 * @returns {void}
 */
export function deactivate() {
  console.log("DinoScan extension is now deactivated!");
}

/**
 * Analyze the currently active Python file
 */
async function analyzeCurrentFile(
  diagnosticProvider: DinoscanDiagnosticProvider,
  statusBar: DinoscanStatusBar,
  output: vscode.OutputChannel,
) {
  const activeEditor = vscode.window.activeTextEditor;
  if (!activeEditor) {
    vscode.window.showWarningMessage("No active file to analyze");
    return;
  }

  if (activeEditor.document.languageId !== "python") {
    vscode.window.showWarningMessage("DinoScan only supports Python files");
    return;
  }

  const findingsCount = await analyzeDocument(
    activeEditor.document,
    diagnosticProvider,
    statusBar,
    output,
  );

  if (findingsCount !== null) {
    const message =
      findingsCount > 0
        ? `DinoScan found ${findingsCount} issue${findingsCount === 1 ? "" : "s"} in ${path.basename(
            activeEditor.document.fileName,
          )}`
        : `DinoScan found no issues in ${path.basename(activeEditor.document.fileName)}`;
    vscode.window.showInformationMessage(message);
  }
}

/**
 * Analyze all Python files in the workspace
 */
async function analyzeWorkspace(
  diagnosticProvider: DinoscanDiagnosticProvider,
  statusBar: DinoscanStatusBar,
  output: vscode.OutputChannel,
) {
  const workspaceFolders = vscode.workspace.workspaceFolders;
  if (!workspaceFolders) {
    vscode.window.showWarningMessage("No workspace folder is open");
    return;
  }

  statusBar.setAnalyzing(true);

  try {
    // Find all Python files
    const pythonFiles = await vscode.workspace.findFiles(
      "**/*.py",
      "**/node_modules/**",
    );

    if (pythonFiles.length === 0) {
      vscode.window.showInformationMessage(
        "No Python files found in workspace",
      );
      return;
    }

    // Show progress
    await vscode.window.withProgress(
      {
        location: vscode.ProgressLocation.Notification,
        title: "DinoScan: Analyzing workspace...",
        cancellable: true,
      },
      async (
        progress: vscode.Progress<{ increment?: number; message?: string }>,
        token: vscode.CancellationToken,
      ) => {
        const increment = 100 / pythonFiles.length;

        for (let i = 0; i < pythonFiles.length; i++) {
          if (token.isCancellationRequested) {
            break;
          }

          const fileUri = pythonFiles[i];
          progress.report({
            increment,
            message: `Analyzing ${path.basename(fileUri.fsPath)} (${i + 1}/${pythonFiles.length})`,
          });

          const document = await vscode.workspace.openTextDocument(fileUri);
          await analyzeDocument(
            document,
            diagnosticProvider,
            statusBar,
            output,
            false,
          );
        }
      },
    );

    const findingsCount = diagnosticProvider.getTotalFindings();
    vscode.window.showInformationMessage(
      `DinoScan analysis complete: ${findingsCount} findings in ${pythonFiles.length} files`,
    );
  } catch (error) {
    vscode.window.showErrorMessage(
      `DinoScan workspace analysis failed: ${error}`,
    );
  } finally {
    statusBar.setAnalyzing(false);
  }
}

/**
 * Analyze a specific document
 */
async function analyzeDocument(
  document: vscode.TextDocument,
  diagnosticProvider: DinoscanDiagnosticProvider,
  statusBar: DinoscanStatusBar,
  output: vscode.OutputChannel,
  showProgress = true,
): Promise<number | null> {
  const config = vscode.workspace.getConfiguration("dinoscan");
  const maxFileSize = config.get<number>("maxFileSize", 1048576); // 1MB default

  // Skip large files
  if (document.getText().length > maxFileSize) {
    const message = `Skipping large file: ${document.fileName} (${document.getText().length} bytes)`;
    console.log(message);
    output.appendLine(`[DinoScan] ${message}`);
    return null;
  }

  if (showProgress) {
    statusBar.setAnalyzing(true);
  }

  try {
    output.appendLine(`[DinoScan] Starting analysis for ${document.fileName}`);
    await runDinoscanAnalysis(document, diagnosticProvider, output);

    const findings = diagnosticProvider.getDiagnostics(document.uri);
    const count = findings.length;
    output.appendLine(
      `[DinoScan] ${count} finding(s) detected in ${document.fileName}`,
    );

    if (showProgress) {
      if (count > 0) {
        statusBar.setFindings(count);
      } else {
        statusBar.setClean();
      }
    }

    return count;
  } catch (error) {
    console.error("DinoScan analysis error:", error);
    output.appendLine(
      `[DinoScan] Analysis failed for ${document.fileName}: ${
        error instanceof Error ? error.message : String(error)
      }`,
    );
    if (showProgress) {
      vscode.window.showErrorMessage(`DinoScan analysis failed: ${error}`);
    }
    return null;
  } finally {
    if (showProgress) {
      statusBar.setAnalyzing(false);
    }
  }
}

/**
 * Run DinoScan analysis on a document
 */
interface DinoscanInvocation {
  command: string;
  args: string[];
}

/**
 * Extracts a fix suggestion from a given message string.
 * Scans for the 'Fix:' marker and returns the suggestion text before the next period or end of string.
 * @param message - The input message containing a fix suggestion.
 * @returns The fix suggestion text, or null if no suggestion is found.
 */
function extractFixSuggestion(message: string): string | null {
  const marker = "Fix:";
  const index = message.indexOf(marker);
  if (index === -1) {
    return null;
  }

  return message
    .slice(index + marker.length)
    .split(/(?:\.\s|$)/)[0]
    .trim();
}

/**
 * Runs DinoScan analysis on a text document, aggregates unique findings, and updates diagnostics.
 * @param document The text document to analyze.
 * @param diagnosticProvider The provider used to update diagnostics based on findings.
 * @param output The output channel for logging analysis progress and results.
 * @returns A promise that resolves when analysis is complete.
 */
async function runDinoscanAnalysis(
  document: vscode.TextDocument,
  diagnosticProvider: DinoscanDiagnosticProvider,
  output: vscode.OutputChannel,
): Promise<void> {
  const config = vscode.workspace.getConfiguration("dinoscan");
  const analysisProfile = config.get<string>("analysisProfile", "standard");
  const excludePatterns = config.get<string[]>("excludePatterns", []);
  const workspaceRoot = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;

  const invocation = findDinoscanExecutable(output);
  if (!invocation) {
    throw new Error(
      "DinoScan not found. Please install DinoScan: pip install dinoscan",
    );
  }

  const configuredAnalyzers = config.get<string[]>(
    "enabledAnalyzers",
    ALL_ANALYZERS,
  );
  const normalizedAnalyzers = configuredAnalyzers
    .map(normalizeAnalyzerName)
    .filter((name): name is AnalyzerName => name !== null);
  const uniqueAnalyzers = Array.from(new Set(normalizedAnalyzers));
  const analyzersToRun: Array<"all" | AnalyzerName> =
    uniqueAnalyzers.length === 0 ||
    uniqueAnalyzers.length === ALL_ANALYZERS.length
      ? ["all"]
      : uniqueAnalyzers;

  const aggregatedResults: DinoscanFinding[] = [];
  const seenKeys = new Set<string>();

  for (const analyzer of analyzersToRun) {
    const results = await executeDinoscanInvocation(
      invocation,
      analyzer,
      document,
      analysisProfile,
      excludePatterns,
      workspaceRoot,
      output,
    );

    results.forEach((result) => {
      const key = `${result.file}:${result.line}:${result.column}:${result.rule_id ?? ""}:${result.message}`;
      if (!seenKeys.has(key)) {
        seenKeys.add(key);
        aggregatedResults.push(result);
      }
    });

    output.appendLine(
      `[DinoScan] Analyzer '${analyzer}' completed with ${results.length} result(s).`,
    );
  }

  diagnosticProvider.updateDiagnostics(document, aggregatedResults);
  output.appendLine(
    `[DinoScan] Aggregated ${aggregatedResults.length} unique finding(s).`,
  );
}

/**
 * Executes a DinoScan analyzer invocation with the specified parameters.
 *
 * @param invocation The DinoScan invocation configuration including command and args.
 * @param analyzer The name of the analyzer to run or "all" to run all analyzers.
 * @param document The VSCode text document to analyze.
 * @param analysisProfile The analysis profile to use.
 * @param excludePatterns Array of glob patterns to exclude from analysis.
 * @param workspaceRoot The workspace root directory or undefined for default.
 * @param output The output channel for logging analyzer output.
 * @returns A promise that resolves to an array of DinoScan findings.
 */
function executeDinoscanInvocation(
  invocation: DinoscanInvocation,
  analyzer: "all" | AnalyzerName,
  document: vscode.TextDocument,
  analysisProfile: string,
  excludePatterns: string[],
  workspaceRoot: string | undefined,
  output: vscode.OutputChannel,
): Promise<DinoscanFinding[]> {
  return new Promise((resolve, reject) => {
    const args = [
      ...invocation.args,
      analyzer,
      document.fileName,
      "--format",
      "json",
      "--profile",
      analysisProfile,
    ];

    excludePatterns.forEach((pattern) => {
      args.push("--exclude", pattern);
    });

    output.appendLine(
      `[DinoScan] Running analyzer '${analyzer}': ${invocation.command} ${args.join(" ")} (cwd=${workspaceRoot ?? "default"})`,
    );

    const child = spawn(invocation.command, args, {
      cwd: workspaceRoot,
    });

    let stdout = "";
    let stderr = "";

    child.stdout?.on("data", (data) => {
      stdout += data.toString();
    });

    child.stderr?.on("data", (data) => {
      stderr += data.toString();
    });

    child.on("close", (code) => {
      if (code === null) {
        reject(new Error("DinoScan process was killed"));
        return;
      }

      if (code !== 0) {
        output.appendLine(
          `[DinoScan] Analyzer '${analyzer}' exited with code ${code}. stderr: ${stderr.trim() || "<empty>"}`,
        );
        reject(new Error(stderr.trim() || `DinoScan exited with code ${code}`));
        return;
      }

      try {
        if (!stdout.trim()) {
          resolve([]);
          return;
        }

        output.appendLine(
          `[DinoScan] Analyzer '${analyzer}' returned ${stdout.trim().length} bytes of JSON results.`,
        );
        const results = JSON.parse(stdout) as DinoscanFinding[];
        resolve(results);
      } catch (parseError) {
        console.error("Failed to parse DinoScan output:", parseError);
        console.error("stdout:", stdout);
        console.error("stderr:", stderr);
        output.appendLine(
          `[DinoScan] Failed to parse output for analyzer '${analyzer}'. See console for details.`,
        );
        reject(new Error(`Failed to parse DinoScan output: ${parseError}`));
      }
    });

    child.on("error", (error) => {
      output.appendLine(
        `[DinoScan] Failed to start analyzer '${analyzer}': ${error.message}`,
      );
      reject(new Error(`Failed to run DinoScan: ${error.message}`));
    });
  });
}

/**
 * Find DinoScan executable in PATH or common locations
 */
/**
 * Finds an executable invocation for the dinoscan tool based on workspace and configuration.
 * @param output - The VSCode output channel for logging.
 * @returns A DinoscanInvocation if a usable invocation is found, otherwise null.
 */
function findDinoscanExecutable(
  output: vscode.OutputChannel,
): DinoscanInvocation | null {
  const config = vscode.workspace.getConfiguration("dinoscan");
  const configuredPath = config.get<string>("executablePath", "").trim();
  const workspaceRoot = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;

  const pythonCandidates = ["python", "python3", "py"];
  const candidateInvocations: DinoscanInvocation[] = [];

  /**
   * Attempts to resolve the given path to an absolute file path relative to the workspace root.
   * @param maybePath - The potential file path to resolve.
   * @returns The resolved absolute path if it exists, otherwise null.
   */
  const tryResolvePath = (maybePath: string): string | null => {
    if (!maybePath) {
      return null;
    }

    const absolutePath = path.isAbsolute(maybePath)
      ? maybePath
      : workspaceRoot
        ? path.join(workspaceRoot, maybePath)
        : maybePath;

    return fs.existsSync(absolutePath) ? absolutePath : null;
  };

  /**
   * Adds candidate invocations for a Python script to the list of potential dinoscan invocations.
   * @param scriptPath - The path to the Python script.
   */
  const pushScriptCandidates = (scriptPath: string | null) => {
    if (!scriptPath) {
      return;
    }

    pythonCandidates.forEach((pythonCommand) => {
      candidateInvocations.push({ command: pythonCommand, args: [scriptPath] });
    });
  };

  /**
   * Adds candidate invocations for the "dinoscan" command and Python module invocations.
   */
  const pushCommandCandidates = () => {
    candidateInvocations.push({ command: "dinoscan", args: [] });
    pythonCandidates.forEach((pythonCommand) => {
      candidateInvocations.push({
        command: pythonCommand,
        args: ["-m", "dinoscan"],
      });
    });
  };

  const configuredScript = configuredPath
    ? tryResolvePath(configuredPath)
    : null;
  if (configuredScript) {
    if (configuredScript.toLowerCase().endsWith(".py")) {
      pushScriptCandidates(configuredScript);
    } else {
      candidateInvocations.push({ command: configuredScript, args: [] });
    }
  } else if (configuredPath) {
    candidateInvocations.push({ command: configuredPath, args: [] });
  }

  if (workspaceRoot) {
    const workspaceScripts = [
      path.join(workspaceRoot, "DinoScan", "dinoscan.py"),
      path.join(workspaceRoot, "DinoScan", "dinoscan_cli.py"),
      path.join(workspaceRoot, "dinoscan.py"),
      path.join(workspaceRoot, "dinoscan_cli.py"),
    ];
    workspaceScripts.forEach((script) =>
      pushScriptCandidates(tryResolvePath(script)),
    );
  }

  const extensionScripts = [
    path.join(__dirname, "..", "..", "dinoscan.py"),
    path.join(__dirname, "..", "..", "dinoscan_cli.py"),
  ];
  extensionScripts.forEach((script) =>
    pushScriptCandidates(tryResolvePath(script)),
  );

  pushCommandCandidates();

  for (const invocation of candidateInvocations) {
    if (isInvocationUsable(invocation, workspaceRoot, output)) {
      return invocation;
    }
  }

  return null;
}

/**
 * Checks whether a given Dinoscan invocation can be executed and responds to the --help flag.
 * @param invocation - The DinoscanInvocation containing the command and its arguments.
 * @param cwd - The current working directory to execute the command in. If undefined, the default working directory is used.
 * @param output - The VSCode OutputChannel where probe results and errors are logged.
 * @returns True if the invocation exits with status 0 when passed --help; otherwise, false.
 */
function isInvocationUsable(
  invocation: DinoscanInvocation,
  cwd: string | undefined,
  output: vscode.OutputChannel,
): boolean {
  try {
    const testArgs = [...invocation.args, "--help"];
    const result = spawnSync(invocation.command, testArgs, {
      cwd,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
      maxBuffer: 1024 * 1024,
    });

    if (result.error) {
      output.appendLine(
        `[DinoScan] Command check failed for ${invocation.command}: ${result.error.message}`,
      );
      return false;
    }

    // Argparse exits with status 0 when --help is supplied.
    const ok = result.status === 0;
    if (!ok) {
      output.appendLine(
        `[DinoScan] Command ${invocation.command} exited with code ${result.status} during probe.`,
      );
    }
    return ok;
  } catch (error) {
    output.appendLine(
      `[DinoScan] Error probing ${invocation.command}: ${String(error)}`,
    );
    return false;
  }
}

/**
 * Check if auto-analysis is enabled
 */
function isAutoAnalysisEnabled(): boolean {
  const config = vscode.workspace.getConfiguration("dinoscan");
  return config.get<boolean>("autoAnalysis", true);
}

/**
 * Toggle auto-analysis setting
 */
async function toggleAutoAnalysis() {
  const config = vscode.workspace.getConfiguration("dinoscan");
  const current = config.get<boolean>("autoAnalysis", true);
  await config.update(
    "autoAnalysis",
    !current,
    vscode.ConfigurationTarget.Global,
  );

  vscode.window.showInformationMessage(
    `DinoScan auto-analysis ${!current ? "enabled" : "disabled"}`,
  );
}

/**
 * Show welcome message for first-time users
 */
function showWelcomeMessage(context: vscode.ExtensionContext) {
  const hasShownWelcome = context.globalState.get<boolean>(
    "hasShownWelcome",
    false,
  );

  if (!hasShownWelcome) {
    vscode.window
      .showInformationMessage(
        "Welcome to DinoScan! Right-click on Python files to start analyzing.",
        "Learn More",
        "Settings",
      )
      .then((selection: string | undefined) => {
        if (selection === "Learn More") {
          vscode.env.openExternal(
            vscode.Uri.parse("https://github.com/DinoAir/DinoScan"),
          );
        } else if (selection === "Settings") {
          vscode.commands.executeCommand(
            "workbench.action.openSettings",
            "dinoscan",
          );
        }
      });

    context.globalState.update("hasShownWelcome", true);
  }
}
