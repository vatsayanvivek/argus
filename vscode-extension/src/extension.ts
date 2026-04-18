// ARGUS IaC Scanner — VSCode extension.
//
// On save (or on command) invokes `argus scan --iac-only --iac-path <ws>
// --output json` in a tmpdir, then parses the resulting JSON into VSCode
// diagnostics. No network calls — everything happens through the local
// argus binary.

import * as vscode from 'vscode';
import * as cp from 'child_process';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

const DIAG_SOURCE = 'argus';

let diagnostics: vscode.DiagnosticCollection;
let status: vscode.StatusBarItem;

interface ArgusFinding {
  id: string;
  severity: string;
  pillar: string;
  resource_id: string;
  resource_name: string;
  resource_type: string;
  title: string;
  detail: string;
  participates_in_chains?: string[];
  location?: { file?: string; line?: number };
}

interface ArgusScan {
  findings: ArgusFinding[];
  chains?: Array<{ id: string; title: string; severity: string }>;
}

export function activate(context: vscode.ExtensionContext) {
  diagnostics = vscode.languages.createDiagnosticCollection(DIAG_SOURCE);
  status = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
  status.text = '$(shield) ARGUS';
  status.tooltip = 'Click to scan this workspace';
  status.command = 'argus.scanWorkspace';
  status.show();

  context.subscriptions.push(
    diagnostics,
    status,
    vscode.commands.registerCommand('argus.scanWorkspace', scanWorkspace),
    vscode.commands.registerCommand('argus.scanFile', scanCurrentFile),
    vscode.commands.registerCommand('argus.clearDiagnostics', () => diagnostics.clear()),
    vscode.workspace.onDidSaveTextDocument(doc => {
      const cfg = vscode.workspace.getConfiguration('argus');
      if (!cfg.get<boolean>('scanOnSave', true)) return;
      if (isIacFile(doc.uri)) scanWorkspace();
    }),
  );
}

export function deactivate() {
  diagnostics?.dispose();
}

function isIacFile(uri: vscode.Uri): boolean {
  const name = path.basename(uri.fsPath).toLowerCase();
  return name.endsWith('.bicep') ||
         name.endsWith('.tf') ||
         name.endsWith('.tfvars') ||
         (name.endsWith('.json') && /(azuredeploy|template|arm).*\.json$/i.test(name));
}

async function scanCurrentFile() {
  const editor = vscode.window.activeTextEditor;
  if (!editor) return;
  const uri = editor.document.uri;
  if (!isIacFile(uri)) {
    vscode.window.showWarningMessage('ARGUS: Not an IaC file (Bicep / ARM / Terraform).');
    return;
  }
  return scanPath(path.dirname(uri.fsPath));
}

async function scanWorkspace() {
  const ws = vscode.workspace.workspaceFolders?.[0];
  if (!ws) {
    vscode.window.showWarningMessage('ARGUS: No workspace folder open.');
    return;
  }
  return scanPath(ws.uri.fsPath);
}

async function scanPath(iacPath: string) {
  const cfg = vscode.workspace.getConfiguration('argus');
  const binary = cfg.get<string>('binaryPath', 'argus');
  const minSeverity = cfg.get<string>('minSeverity', 'LOW');
  const compliance = cfg.get<string>('complianceFilter', '');

  const outDir = fs.mkdtempSync(path.join(os.tmpdir(), 'argus-vscode-'));
  const args = ['scan', '--iac-only', '--iac-path', iacPath, '--output', 'json', '--output-dir', outDir];
  if (compliance) {
    args.push('--compliance', compliance);
  }

  status.text = '$(sync~spin) ARGUS scanning…';
  try {
    await new Promise<void>((resolve, reject) => {
      cp.execFile(binary, args, { timeout: 120_000 }, (err, stdout, stderr) => {
        // IaC scans can return non-zero when findings exist — that's not an error.
        if (err && typeof err === 'object' && (err as any).code !== undefined && (err as any).code !== 1 && (err as any).code !== 0) {
          console.error('argus stderr:', stderr);
          reject(new Error(stderr || (err as Error).message));
          return;
        }
        resolve();
      });
    });

    const jsonPath = findScanJson(outDir);
    if (!jsonPath) throw new Error('ARGUS produced no JSON output');

    const scan: ArgusScan = JSON.parse(fs.readFileSync(jsonPath, 'utf8'));
    publishDiagnostics(iacPath, scan, minSeverity);
    const count = scan.findings?.length || 0;
    status.text = `$(shield) ARGUS ${count} finding(s)`;
    status.tooltip = `Last scan: ${count} finding(s). Click to rescan.`;
  } catch (e: any) {
    vscode.window.showErrorMessage(`ARGUS: ${e.message}`);
    status.text = '$(shield) ARGUS (error)';
  } finally {
    try { fs.rmSync(outDir, { recursive: true, force: true }); } catch {}
  }
}

function findScanJson(dir: string): string | null {
  const entries = fs.readdirSync(dir);
  const hit = entries.find(n => n.startsWith('argus_') && n.endsWith('.json'));
  return hit ? path.join(dir, hit) : null;
}

function publishDiagnostics(iacPath: string, scan: ArgusScan, minSeverity: string) {
  diagnostics.clear();
  const minRank = severityRank(minSeverity);
  const byFile = new Map<string, vscode.Diagnostic[]>();

  for (const f of scan.findings || []) {
    if (severityRank(f.severity) > minRank) continue;

    const loc = resolveLocation(iacPath, f);
    if (!loc) continue;

    const range = new vscode.Range(loc.line, 0, loc.line, 200);
    const diag = new vscode.Diagnostic(
      range,
      `${f.id}: ${f.title}\n${f.detail || ''}`.trim(),
      severityToCode(f.severity),
    );
    diag.source = DIAG_SOURCE;
    diag.code = {
      value: f.id,
      target: vscode.Uri.parse(`https://github.com/vatsayanvivek/argus/blob/main/docs/content/rules/${f.id}.md`),
    };
    if (f.participates_in_chains?.length) {
      diag.message += `\n(chains: ${f.participates_in_chains.join(', ')})`;
    }

    const uri = vscode.Uri.file(loc.file);
    const list = byFile.get(uri.fsPath) || [];
    list.push(diag);
    byFile.set(uri.fsPath, list);
  }

  for (const [fpath, list] of byFile.entries()) {
    diagnostics.set(vscode.Uri.file(fpath), list);
  }
}

function resolveLocation(iacPath: string, f: ArgusFinding): { file: string; line: number } | null {
  // ARGUS includes file/line hints when a finding comes from IaC.
  if (f.location?.file) {
    const p = path.isAbsolute(f.location.file) ? f.location.file : path.join(iacPath, f.location.file);
    if (fs.existsSync(p)) {
      return { file: p, line: Math.max(0, (f.location.line || 1) - 1) };
    }
  }
  // Fallback: pin to the first IaC file we find in the workspace.
  const fallback = firstIacFile(iacPath);
  if (!fallback) return null;
  return { file: fallback, line: 0 };
}

function firstIacFile(dir: string): string | null {
  try {
    for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
      if (e.isFile()) {
        const uri = vscode.Uri.file(path.join(dir, e.name));
        if (isIacFile(uri)) return uri.fsPath;
      }
    }
  } catch { /* ignore */ }
  return null;
}

function severityRank(s: string): number {
  switch (s.toUpperCase()) {
    case 'CRITICAL': return 0;
    case 'HIGH': return 1;
    case 'MEDIUM': return 2;
    case 'LOW': return 3;
    default: return 4;
  }
}

function severityToCode(s: string): vscode.DiagnosticSeverity {
  switch (s.toUpperCase()) {
    case 'CRITICAL':
    case 'HIGH':
      return vscode.DiagnosticSeverity.Error;
    case 'MEDIUM':
      return vscode.DiagnosticSeverity.Warning;
    case 'LOW':
      return vscode.DiagnosticSeverity.Information;
    default:
      return vscode.DiagnosticSeverity.Hint;
  }
}
