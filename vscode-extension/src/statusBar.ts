/**
 * DinoScan Status Bar
 *
 * Provides status bar integration showing analysis progress,
 * findings count, and quick actions.
 */

import * as vscode from 'vscode';

export class DinoscanStatusBar {
  private readonly statusBarItem: vscode.StatusBarItem;

  constructor() {
    this.statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
    this.statusBarItem.command = 'dinoscan.showReport';
    this.statusBarItem.show();
    this.setReady();
  }

  /**
   * Set status to ready state
   */
  public setReady(): void {
    this.statusBarItem.text = '$(search) DinoScan';
    this.statusBarItem.tooltip = 'DinoScan: Ready to analyze';
    this.statusBarItem.backgroundColor = undefined;
  }

  /**
   * Set status to analyzing state
   */
  public setAnalyzing(analyzing: boolean): void {
    if (analyzing) {
      this.startAnalyzing();
    } else {
      this.setReady();
    }
  }

  /**
   * Set status to show analysis is starting
   */
  private startAnalyzing(): void {
    this.statusBarItem.text = '$(sync~spin) DinoScan: Analyzing...';
    this.statusBarItem.tooltip = 'DinoScan: Analysis in progress';
    this.statusBarItem.backgroundColor = undefined;
  }

  /**
   * Set status showing findings count
   */
  public setFindings(count: number): void {
    if (count === 0) {
      this.setClean();
      return;
    }

    const severity = this.getSeverityIcon(count);
    this.statusBarItem.text = `${severity} DinoScan: ${count} issue${count > 1 ? 's' : ''}`;
    this.statusBarItem.tooltip = `DinoScan: ${count} finding${count > 1 ? 's' : ''} found. Click to view report.`;

    // Color based on findings count
    if (count > 10) {
      this.statusBarItem.backgroundColor = new vscode.ThemeColor('statusBarItem.errorBackground');
    } else if (count > 5) {
      this.statusBarItem.backgroundColor = new vscode.ThemeColor('statusBarItem.warningBackground');
    } else {
      this.statusBarItem.backgroundColor = undefined;
    }
  }

  /**
   * Set status to clean (no issues)
   */
  public setClean(): void {
    this.statusBarItem.text = '$(check) DinoScan: Clean';
    this.statusBarItem.tooltip = 'DinoScan: No issues found';
    this.statusBarItem.backgroundColor = undefined;
  }

  /**
   * Set error status
   */
  public setError(message: string): void {
    this.statusBarItem.text = '$(error) DinoScan: Error';
    this.statusBarItem.tooltip = `DinoScan Error: ${message}`;
    this.statusBarItem.backgroundColor = new vscode.ThemeColor('statusBarItem.errorBackground');
  }

  /**
   * Hide the status bar item
   */
  public hide(): void {
    this.statusBarItem.hide();
  }

  /**
   * Show the status bar item
   */
  public show(): void {
    this.statusBarItem.show();
  }

  /**
   * Get appropriate severity icon based on findings count
   */
  private getSeverityIcon(count: number): string {
    if (count > 10) {
      return '$(error)';
    } else if (count > 5) {
      return '$(warning)';
    } else if (count > 0) {
      return '$(info)';
    }
    return '$(check)';
  }

  /**
   * Update status bar visibility based on configuration
   */
  public updateVisibility(): void {
    const config = vscode.workspace.getConfiguration('dinoscan');
    const showStatusBar = config.get<boolean>('showStatusBar', true);

    if (showStatusBar) {
      this.show();
    } else {
      this.hide();
    }
  }

  /**
   * Dispose of the status bar item
   */
  public dispose(): void {
    this.statusBarItem.dispose();
  }
}
