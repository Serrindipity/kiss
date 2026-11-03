import { useEffect, useRef, useState } from 'react';
import { ArrowLeft, ChevronDown, Download, Play, Upload } from 'lucide-react';
import { api, displayTime, hostName } from './api';
import { relativeTime } from './activity';
import useEscape from './useEscape';
import { routeHref, shouldNavigate } from './useRoute';
import './automation.css';
import AutomationResult from './AutomationResult';
import { checkTitle, checkState, isToolSetup } from './automationResults';

const active = run => ['Queued', 'Running'].includes(run?.status);
export default function Automation({ state, runId, onSelect }) {
  const [runs, setRuns] = useState([]);
  const [dependencies, setDependencies] = useState(null);
  const [catalog, setCatalog] = useState([]);
  const [run, setRun] = useState(null);
  const [adding, setAdding] = useState(false);
  const [error, setError] = useState('');
  const [loadError, setLoadError] = useState('');
  const [busy, setBusy] = useState(false);
  const [filter, setFilter] = useState('');
  const [statusFilter, setStatusFilter] = useState('checks');
  const [limit, setLimit] = useState(50);
  const [form, setForm] = useState({ preset: 'anonymous', listener: '', adcs: false, adcs_ca_endpoints: false, host_id: '', domain: '', modules: ['dns', 'services', 'smb', 'ldap'], ldap_host: '', ldap_transport: 'both', bind_user: '', password: '', guest: false, ms17_010: false, timeout: 600 });
  const upload = useRef(null);
  const [revision, setRevision] = useState(0);
  useEscape(() => { if (adding) { setAdding(false); setForm(old => ({ ...old, password: '' })); } else if (runId) onSelect(null); });
  useEffect(() => {
    let cancelled = false;
    let timer;
    setRun(null); setError(''); setLimit(50); setFilter(''); setStatusFilter('checks');
    async function load() {
      try {
        const [list, detail] = await Promise.all([api('/automation'), runId ? api(`/automation/${encodeURIComponent(runId)}`) : Promise.resolve(null)]);
        if (cancelled) return;
        setRuns(list.runs); setDependencies(list.dependencies); setCatalog(list.catalog || []); setRun(detail); setLoadError('');
      } catch (err) { if (!cancelled) setLoadError(err.message); }
      if (!cancelled) timer = setTimeout(load, 2000);
    }
    void load();
    return () => { cancelled = true; clearTimeout(timer); };
  }, [runId, revision]);
  function change(key, value) { setForm(old => ({ ...old, [key]: value })); }
  function chooseHost(id) {
    const host = state.hosts.find(h => h.id === id);
    const network = state.networks.find(n => n.id === host?.network_id);
    setForm(old => ({ ...old, host_id: id, domain: network?.dns_zone || old.domain, ldap_host: host?.hostname || '' }));
  }
  async function start(plan) {
    setBusy(true); setError('');
    try {
      const result = await api('/automation', { method: 'POST', json: { ...form, bind_user: form.preset === 'domain' ? form.bind_user : '', password: form.preset === 'domain' ? form.password : '', plan } });
      setAdding(false); change('password', ''); onSelect(result.id); setRevision(value => value + 1);
    } catch (err) { setError(err.message); }
    finally { setBusy(false); }
  }
  async function importFile(file) {
    if (!file) return;
    if (file.size > 20 * 1024 * 1024) { setError('Choose a results.json smaller than 20 MB.'); return; }
    setBusy(true); setError('');
    try {
      const result = await api('/automation/import', { method: 'POST', body: file });
      setAdding(false); onSelect(result.id); setRevision(value => value + 1);
    } catch (err) { setError(err.message); }
    finally { setBusy(false); }
  }
  async function cancel() {
    setBusy(true); setError('');
    try { await api(`/automation/${runId}/cancel`, { method: 'POST' }); setRevision(value => value + 1); }
    catch (err) { setError(err.message); }
    finally { setBusy(false); }
  }
  const domainAccount = form.preset === 'domain';
  const included = catalog.filter(check => check.authenticated === domainAccount);
  const required = domainAccount ? ['nxc', ...(form.adcs ? ['certipy'] : [])] : ['nxc', 'nmap'];
  const missing = dependencies ? required.filter(tool => !dependencies[tool]) : [];
  const selected = included.length;
  const rows = run?.report?.results || [];
  const diagnostics = rows.filter(isToolSetup).length;
  const effectiveFilter = statusFilter;
  const attention = rows.filter(row => checkState(row).tone === 'attention').length;
  const skipped = rows.filter(row => row.status === 'not_tested' && row.reason !== 'plan_only').length;
  const visible = rows.filter(row => `${checkTitle(row)} ${row.id || row.path} ${checkState(row).label} `.toLowerCase().includes(filter.toLowerCase()) && (effectiveFilter === 'all' || (effectiveFilter === 'diagnostics' ? isToolSetup(row) : effectiveFilter === 'checks' ? !isToolSetup(row) : effectiveFilter === 'attention' ? checkState(row).tone === 'attention' : row.status === 'not_tested' && row.reason !== 'plan_only')));

  return <main className="automation-page">
    <header className="page-header"><h1>Automation</h1><div className="row wrap" hidden={adding}><button disabled={busy} onClick={() => upload.current.click()}><Upload size={16} />Import results</button><button className="primary" onClick={() => { setAdding(true); onSelect(null); }}><Play size={16} />New run</button></div></header>
    <input ref={upload} type="file" accept=".json,application/json" hidden onChange={event => { void importFile(event.target.files[0]); event.target.value = ''; }} />
    {(error || loadError) && <p className="error" role="alert">{error || loadError}</p>}
    {adding ? <form className="automation-form" onSubmit={event => { event.preventDefault(); void start(false); }}>
      <div className="row between"><h2>New automation run</h2><button type="button" className="quiet" onClick={() => { setAdding(false); change('password', ''); }}>Cancel</button></div>
      <div className="automation-run-types" role="group" aria-label="Run preset">{[['anonymous', 'Anonymous checks', 'NetExec service access and vulnerability checks'], ['domain', 'Domain account checks', 'NetExec checks with one known account']].map(([id, name, description]) => <button type="button" key={id} aria-pressed={form.preset === id} onClick={() => setForm(old => ({ ...old, preset: id, password: '', listener: '' }))}><strong>{name}</strong><span className="hint">{description}</span></button>)}</div>
      <div className="automation-fields"><label className="field">Host<select required value={form.host_id} onChange={event => chooseHost(event.target.value)}><option value="">Choose a host in scope</option>{state.hosts.map(host => <option key={host.id} value={host.id}>{hostName(host)} · {host.address}</option>)}</select></label><label className="field">Domain<input required placeholder="corp.local" value={form.domain} onChange={event => change('domain', event.target.value)} /></label></div>
      {domainAccount && <div className="automation-fields"><label className="field">Domain username<input required placeholder="reader or reader@corp.local" autoComplete="off" value={form.bind_user} onChange={event => change('bind_user', event.target.value)} /></label><label className="field">Password<input required type="password" autoComplete="new-password" value={form.password} onChange={event => change('password', event.target.value)} /></label></div>}
      <p className="hint">{domainAccount ? 'Runs the account-based NetExec checks using one known credential.' : 'Uses NetExec for FTP, SMB, LDAP/LDAPS, RDP and WinRM access checks and the anonymous-capable probes. MS17-010 uses Nmap.'}</p>
      <details className="automation-options"><summary>Included checks<ChevronDown size={16} /></summary><p className="hint">Each result retains the tool’s output. Unsupported modules or options are marked skipped.</p><ul className="automation-included">{included.map(check => <li key={check.name}><strong>{checkTitle({ id: check.name })}</strong><span className="hint">{check.note}</span></li>)}</ul>{domainAccount && form.adcs && <p className="hint">AD CS analysis with Certipy (DC-only by default).</p>}</details>
      <details className="automation-options"><summary>Connection &amp; optional settings<ChevronDown size={16} /></summary>
        <div className="automation-fields"><label className="field">Timeout per command (seconds)<input type="number" min="10" max="600" value={form.timeout} onChange={event => change('timeout', Number(event.target.value))} /></label></div>
        <label className="field">Coercion receiver (optional)<input placeholder="Your lab receiver IP or hostname" value={form.listener} onChange={event => change('listener', event.target.value)} /><span className="hint">Leave empty for RPC interface checks. Set a receiver to attempt callbacks; confirm them using receiver evidence.</span></label>
        {domainAccount && <><label className="check"><input type="checkbox" checked={form.adcs} onChange={event => setForm(old => ({ ...old, adcs: event.target.checked, adcs_ca_endpoints: false }))} />Include AD CS analysis with Certipy</label>{form.adcs && <label className="check"><input type="checkbox" checked={form.adcs_ca_endpoints} onChange={event => change('adcs_ca_endpoints', event.target.checked)} />Also contact discovered CAs and enrollment endpoints</label>}</>}
      </details>
      {missing.length > 0 && <p className="notice">Missing server tools: {missing.join(', ')}. Install them to run this preset. Command preview is still available.</p>}
      <p className="hint">Runs from the KISS server against this host. Results are observations to review, not automatic findings.</p><div className="row wrap"><button className="primary" disabled={busy || !selected || missing.length > 0}>{busy ? 'Working…' : domainAccount ? 'Run domain checks' : 'Run anonymous checks'}</button><button type="button" disabled={busy || !form.host_id || !form.domain || !selected || (domainAccount && !form.bind_user)} onClick={() => start(true)}>Preview commands</button><span className="hint">Preview makes no network requests.</span></div>
    </form> : runId ? run ? <section>
      <button className="quiet" onClick={() => { onSelect(null); setFilter(''); }}><ArrowLeft size={16} />All runs</button>
      <div className="automation-run-heading"><div><h2>{run.target}</h2><p className="hint">{run.preset === 'anonymous' ? 'Anonymous checks' : run.preset === 'domain' ? 'Domain account checks' : run.collector === 'lab' ? 'Lab checks' : run.status === 'Imported' ? 'Imported results' : 'Directory collection'} · {run.domain} · {run.actor} · <time title={displayTime(run.created_at)}>{relativeTime(run.created_at)}</time></p></div><div className="row wrap"><strong>{run.status}</strong>{active(run) && <button disabled={busy} onClick={cancel}>Cancel run</button>}{run.download && <a className="button small" href={`/api/automation/${run.id}/download`}><Download size={15} />Evidence ZIP</a>}</div></div>
      <p className="hint">{rows.length - diagnostics} checks{attention > 0 && ` · ${attention} collection issues`}{skipped > 0 && ` · ${skipped} skipped`} · Tool output is shown as reported.</p>
      {run.error && <p className="error">{run.error}</p>}
      {run.status === 'Imported' && <p className="hint">Imported JSON includes structured results. Separate stdout/stderr files remain with the original collection.</p>}
      <div className="automation-result-tools"><input className="automation-search" aria-label="Filter checks" placeholder="Filter checks or status…" value={filter} onChange={event => { setFilter(event.target.value); setLimit(50); }} /><select aria-label="Filter result status" value={effectiveFilter} onChange={event => { setStatusFilter(event.target.value); setLimit(50); }}><option value="checks">Check results</option><option value="diagnostics">Diagnostics ({diagnostics})</option><option value="all">Full log</option><option value="attention">Collection issues ({attention})</option><option value="skipped">Skipped ({skipped})</option></select></div>
      {visible.slice(0, limit).map((row, index) => <AutomationResult key={`${run.id}:${row.id || row.path}:${index}`} row={row} />)}
      {visible.length > limit && <button className="small" onClick={() => setLimit(value => value + 50)}>Show more ({visible.length - limit} remaining)</button>}
      {rows.length > 0 && !visible.length && <p className="muted">No results match these filters.</p>}
      {!rows.length && <p className="muted">{active(run) ? 'Waiting for the first result…' : 'No check results were recorded.'}</p>}
      {run.log && <details className="automation-options"><summary>Collector log<ChevronDown size={16} /></summary><pre>{run.log}</pre></details>}
    </section> : <p role="status">{loadError ? 'Could not load this run.' : 'Loading run…'}</p> : <section aria-label="Automation runs">
      {!!runs.length && <h2 className="automation-list-heading">Recent runs</h2>}
      {!runs.length && <div className="empty-state"><h2>No runs yet</h2><p>Run checks against a domain controller, or import collector results. Your team’s runs and evidence will appear here.</p><button onClick={() => setAdding(true)}>Set up DC checks</button></div>}
      {runs.map(item => <a className="automation-run" key={item.id} href={routeHref({ page: 'automation', run: item.id })} onClick={event => { if (shouldNavigate(event)) { event.preventDefault(); onSelect(item.id); } }}><div><strong>{item.target}</strong><span className="hint">{item.preset === 'anonymous' ? 'Anonymous checks' : item.preset === 'domain' ? 'Domain account checks' : item.collector === 'lab' ? 'Lab checks' : item.status === 'Imported' ? 'Imported results' : 'Directory collection'} · {item.domain} · {item.actor} · <time title={displayTime(item.created_at)}>{relativeTime(item.created_at)}</time></span></div><span>{item.status}<small className="hint">{item.checks} checks</small></span></a>)}
    </section>}
    {!adding && !runId && <details className="automation-options"><summary>Tools &amp; report template<ChevronDown size={16} /></summary><p>For Windows, run Collect-DomainChecks.ps1 with RSAT. For a copied SYSVOL share, run check_sysvol.py locally. Import the resulting JSON above.</p><a className="button small" href="/api/automation/collectors"><Download size={15} />Download collectors &amp; instructions</a> <a className="button small" href="/api/automation/report-template"><Download size={15} />Report template</a>{dependencies && <p className="hint">{Object.entries(dependencies).map(([name, found]) => `${name}: ${found ? 'installed' : 'missing'}`).join(' · ')}</p>}</details>}
  </main>;
}
