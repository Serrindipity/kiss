import { ChevronDown } from 'lucide-react';
import { checkTitle, checkState, cleanOutput, formatCommand } from './automationResults';

export default function AutomationResult({ row }) {
  const state = checkState(row);
  const stdout = cleanOutput(row.stdout_text);
  const stderr = cleanOutput(row.stderr_text);
  const missingFiles = ['stdout', 'stderr'].some(stream => row[stream] && typeof row[stream + '_text'] !== 'string');
  const savedData = row.content ?? row.data ?? row.indicators;
  const fallback = !stdout && !stderr && savedData != null
    ? typeof savedData === 'string' ? savedData : JSON.stringify(savedData, null, 2)
    : '';
  const message = row.reason === 'plan_only' ? 'Preview only. Command was not run.'
    : row.error || row.reason || row.parse_error
      || (missingFiles ? 'Output files were not included in this import.'
        : row.status === 'not_tested' ? 'This check was not run.'
          : 'The tool returned no output. Access was not confirmed.');

  return <details className="automation-result">
    <summary><span className="automation-result-heading"><strong>{checkTitle(row)}</strong></span><span className={`automation-status ${state.tone}`}>{state.label}</span><ChevronDown size={16} /></summary>
    <div className="automation-evidence">
      {Array.isArray(row.command) && <><h4>Command</h4><pre><code>{formatCommand(row.command)}</code></pre></>}
      <h4>Output</h4>
      {stdout && <pre>{stdout}</pre>}
      {stderr && <><span className="hint">stderr</span><pre>{stderr}</pre></>}
      {fallback && <pre>{fallback}</pre>}
      {!stdout && !stderr && !fallback && <p className="hint">{message}</p>}
      {(stdout || stderr || fallback) && (row.error || row.reason || row.parse_error) && row.reason !== 'plan_only' && <p className="hint">{row.error || row.reason || row.parse_error}</p>}
      {(row.stdout_truncated || row.stderr_truncated) && <p className="hint">Output shortened. Download the evidence ZIP for the full files.</p>}
    </div>
  </details>;
}
