import { useState } from 'react';
import { ArrowLeft, Download, Plus, Search } from 'lucide-react';
import { api, displayTime, hostName, portName } from './api';
import MarkdownEditor, { MarkdownView } from './MarkdownEditor';
import useDraft from './useDraft';
import useEscape from './useEscape';

function ScopePicker({ hosts, value, onChange }) {
  const [search, setSearch] = useState('');
  function selectHost(host, selected) {
    onChange(selected ? [...value, { host_id: host.id, ports: [] }] : value.filter(item => item.host_id !== host.id));
  }
  function selectPort(hostId, port, selected) {
    onChange(value.map(item => item.host_id === hostId ? { ...item, ports: selected ? [...item.ports, port] : item.ports.filter(p => p !== port) } : item));
  }
  return <fieldset className="scope-picker"><legend>Scope <span className="hint">{value.length} selected</span></legend>
    <p className="hint">Select hosts, then specific ports. Leave ports unchecked for a host-wide finding.</p>
    <div className="search"><Search size={16} /><input aria-label="Find hosts for finding scope" value={search} onChange={e => setSearch(e.target.value)} placeholder="Find a host…" /></div>
    <div className="scope-options">{hosts.filter(h => `${h.hostname} ${h.address}`.toLowerCase().includes(search.toLowerCase())).map(host => {
      const selected = value.find(item => item.host_id === host.id);
      return <div className="scope-option" key={host.id}>
        <label className="check"><input type="checkbox" checked={!!selected} onChange={e => selectHost(host, e.target.checked)} /><span>{hostName(host)}<small>{host.address}</small></span></label>
        {selected && <div className="port-options">{host.ports.length ? host.ports.map(port => <label className="port-option" key={portName(port)}><input type="checkbox" checked={selected.ports.includes(portName(port))} onChange={e => selectPort(host.id, portName(port), e.target.checked)} /><code>{portName(port)}</code><span className="hint">{port.service}</span></label>) : <span className="hint">Host-wide. No ports imported yet.</span>}</div>}
      </div>;
    })}{!hosts.length && <p className="hint">Add hosts in Scope before creating a finding.</p>}</div>
  </fieldset>;
}

function FindingEditor({ record, state, onBack, onSaved }) {
  const initial = record || { title: '', description: '', steps: '', remediation: '', finders: [state.username], scope: [], status: 'Draft', revision: 0 };
  const draftKey = `kiss:${state.username}:finding:${record?.id || 'new'}`;
  const { value, setValue, dirty, accept } = useDraft(draftKey, initial);
  const [busy, setBusy] = useState(false);
  const [uploads, setUploads] = useState({});
  const [error, setError] = useState('');
  const [message, setMessage] = useState('');
  const [preview, setPreview] = useState(false);
  useEscape(() => {
    if (!dirty || window.confirm('Leave without saving? Your changes are saved only in this browser tab. Teammates will not see them until you save the finding.')) onBack();
  });
  const latest = state.findings.find(f => f.id === value.id);
  const conflict = latest && latest.revision !== value.revision;
  const uploading = Object.values(uploads).some(Boolean);
  function update(field, next) { setValue(old => ({ ...old, [field]: next })); setMessage(''); }
  async function save(event) {
    event.preventDefault(); setBusy(true); setError('');
    try {
      const saved = await api(value.id ? `/findings/${value.id}` : '/findings', { method: value.id ? 'PUT' : 'POST', json: value });
      accept(saved);
      // New findings move to their permanent key after saving.
      if (!record?.id) sessionStorage.removeItem(draftKey);
      setMessage('Saved to team workspace.');
      onSaved(saved);
    } catch (err) { setError(err.message); }
    finally { setBusy(false); }
  }
  return <main className="finding-editor">
    <button className="quiet back-link" onClick={onBack}><ArrowLeft size={16} /> Findings</button>
    <form onSubmit={save}>
      <header className="page-header"><h1>{value.id ? 'Edit finding' : 'New finding'}</h1><div className="row"><button type="button" onClick={() => setPreview(v => !v)}>{preview ? 'Edit report' : 'Preview report'}</button><button className="primary" disabled={busy || uploading}>{busy ? 'Saving…' : 'Save finding'}</button></div></header>
      <div className="save-status hint" role="status">{message || (dirty ? 'Draft kept in this browser tab. Save to share with the team.' : 'Changes are shared when you save.')}</div>
      {error && <p className="error" role="alert">{error}</p>}
      {conflict && <div className="notice"><p>This finding has a newer server version. Copy any changes you want to keep before loading it.</p><button type="button" onClick={() => { if (!dirty || window.confirm('Replace this local draft with the latest server version?')) { accept(latest); setError(''); } }}>Load latest version</button></div>}
      {preview ? <article className="report-preview"><h2>{value.title || 'Untitled finding'}</h2><p className="muted">{value.status} · Found by {value.finders.join(', ') || 'No finder selected'}</p><h3>Scope</h3><ul>{value.scope.map(item => { const host = state.hosts.find(h => h.id === item.host_id); return <li key={item.host_id}>{host ? hostName(host) : 'Unknown host'}: {item.ports.join(', ') || 'Host-wide'}</li>; })}</ul>{[['Description', 'description'], ['Steps to reproduce', 'steps'], ['Remediation', 'remediation']].map(([label, key]) => <section key={key}><h3>{label}</h3><MarkdownView>{value[key]}</MarkdownView></section>)}</article> :
        <div className="finding-columns"><div className="finding-body">
          <label className="field title-field">Vulnerability title<input required maxLength={250} value={value.title} onChange={e => update('title', e.target.value)} placeholder="A clear, specific finding title" autoFocus /></label>
          <MarkdownEditor label="Vulnerability description" value={value.description} onChange={text => update('description', text)} onBusyChange={busy => setUploads(old => ({ ...old, description: busy }))} placeholder="What is vulnerable, and what is the impact?" />
          <MarkdownEditor label="Steps to reproduce" value={value.steps} onChange={text => update('steps', text)} onBusyChange={busy => setUploads(old => ({ ...old, steps: busy }))} placeholder={'1. Connect to the affected host.\n2. …\n\nPaste screenshots and command output here.'} />
          <MarkdownEditor label="Remediation steps" value={value.remediation} onChange={text => update('remediation', text)} onBusyChange={busy => setUploads(old => ({ ...old, remediation: busy }))} placeholder="Describe the specific change needed to resolve the issue." />
        </div><aside className="finding-context">
          <label className="field">Report status<select value={value.status} onChange={e => update('status', e.target.value)}><option>Draft</option><option>Ready</option></select></label>
          <fieldset className="finders"><legend>Finders</legend><div className="finder-options">{state.users.map(user => <label className="finder-option" key={user}><input type="checkbox" checked={value.finders.includes(user)} onChange={e => update('finders', e.target.checked ? [...value.finders, user] : value.finders.filter(u => u !== user))} />{user}</label>)}</div></fieldset>
          <ScopePicker hosts={state.hosts} value={value.scope} onChange={next => update('scope', next)} />
        </aside></div>}
    </form>
  </main>;
}

export default function Findings({ state, editing, setEditing, refresh }) {
  const [message, setMessage] = useState('');
  const [query, setQuery] = useState('');
  const [status, setStatus] = useState('');
  if (editing) return <FindingEditor key={editing.id || 'new'} record={editing === 'new' ? null : editing} state={state} onBack={() => setEditing(null)} onSaved={() => { setQuery(''); setStatus(''); setMessage('Finding saved.'); setEditing(null); refresh(); }} />;
  const findings = state.findings.filter(f => `${f.title} ${f.description} ${f.finders.join(' ')}`.toLowerCase().includes(query.toLowerCase()) && (!status || f.status === status));
  return <main className="findings-main">
    <header className="page-header"><h1>Findings</h1><div className="row"><a className="button" href="/api/export"><Download /> Export Markdown</a><button className="primary" onClick={() => setEditing('new')}><Plus /> New finding</button></div></header>
    {message && <p className="hint credential-saved" role="status">{message}</p>}
    <div className="toolbar"><div className="search"><Search /><input aria-label="Search findings" placeholder="Search findings or finders…" value={query} onChange={e => setQuery(e.target.value)} /></div><select aria-label="Filter finding status" value={status} onChange={e => setStatus(e.target.value)}><option value="">All status</option><option>Draft</option><option>Ready</option></select></div>
    {findings.length ? <div className="table-scroll"><table><thead><tr><th>Finding</th><th>Scope</th><th>Finders</th><th>Status</th><th>Updated</th></tr></thead><tbody>{findings.map(f => <tr key={f.id} onClick={() => setEditing(f)}><td><button className="table-link" onClick={() => setEditing(f)}>{f.title}</button></td><td>{f.scope.length} {f.scope.length === 1 ? 'host' : 'hosts'}</td><td>{f.finders.join(', ')}</td><td><span className={`status status-${f.status.toLowerCase()}`}>{f.status}</span></td><td className="muted">{displayTime(f.updated_at)}</td></tr>)}</tbody></table></div> : <div className="empty-state"><h2>{state.findings.length ? 'No matching findings' : 'Turn evidence into a finding'}</h2><p>{state.findings.length ? 'Try a different search or status.' : 'Start from a host to prefill its scope, or create a finding here and select the affected hosts and ports.'}</p><button onClick={() => setEditing('new')}>New finding</button></div>}
  </main>;
}
