import { useEffect, useRef, useState } from 'react';
import { ArrowLeft, ChevronDown, Maximize2, Copy, Plus, Search, X } from 'lucide-react';
import { api, hostName } from './api';
import MarkdownEditor, { MarkdownView } from './MarkdownEditor';
import useDraft from './useDraft';
import useEscape from './useEscape';

const types = { domain: 'Domain user', local: 'Local user', service: 'Service account', api: 'API / token', ssh: 'SSH key', other: 'Other' };
const blank = username => ({ kind: '', username: '', secret: '', secret_type: 'Password', domain: '', host_id: null, system: '', service: '', notes: '', status: 'Valid', finder: username, revision: 0 });

function scopeText(credential, hosts) {
  const host = hosts.find(h => h.id === credential.host_id);
  const system = host ? `${hostName(host)} (${host.address})` : credential.system;
  if (credential.kind === 'domain') return credential.domain;
  return [credential.service, system].filter(Boolean).join(' · ');
}

function CopyButton({ value, label }) {
  const [message, setMessage] = useState('');
  async function copy() {
    try {
      if (navigator.clipboard && window.isSecureContext) await navigator.clipboard.writeText(value);
      else {
        const previous = document.activeElement;
        const input = document.createElement('textarea');
        input.value = value; input.style.position = 'fixed'; input.style.left = '-9999px';
        document.body.append(input); input.select();
        try { if (!document.execCommand('copy')) throw new Error('Clipboard unavailable'); }
        finally { input.remove(); previous?.focus(); }
      }
      setMessage('Copied');
    } catch { setMessage('Select the text to copy'); }
  }
  return <span className="copy-control"><button className="icon-button" title={`Copy ${label}`} aria-label={`Copy ${label}`} onClick={copy}><Copy size={15} /></button><span className="hint" role="status">{message}</span></span>;
}

function CredentialForm({ record, state, onClose, onSaved }) {
  const { value, setValue, dirty, accept } = useDraft(`kiss:${state.username}:credential:${record?.id || 'new'}`, record || blank(state.username));
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [notesOpen, setNotesOpen] = useState(Boolean(value.notes));
  const latest = (state.credentials || []).find(c => c.id === record?.id);
  const conflict = latest && latest.revision !== value.revision;
  const needsSystem = ['local', 'service', 'ssh'].includes(value.kind);
  const needsService = ['service', 'api', 'other'].includes(value.kind);
  function update(key, next) { setValue(old => ({ ...old, [key]: next })); }
  function chooseType(kind) {
    setValue(old => ({ ...old, kind, domain: '', host_id: null, system: '', service: '', secret_type: kind === 'api' ? 'Token' : kind === 'ssh' ? 'Private key' : 'Password' }));
  }
  async function save(event) {
    event.preventDefault(); setBusy(true); setError('');
    try {
      const saved = await api(value.id ? `/credentials/${value.id}` : '/credentials', { method: value.id ? 'PUT' : 'POST', json: value });
      accept(saved); await onSaved();
    } catch (err) { setError(err.message); }
    finally { setBusy(false); }
  }
  return <form className="credential-form" onSubmit={save}>
    <button type="button" className="quiet back-link" onClick={onClose}><ArrowLeft size={16} /> Credentials</button>
    <header className="page-header"><h1>{record?.id ? 'Edit credential' : 'New credential'}</h1></header>
    <div className="credential-fields">
      <label className="field">Credential type<select autoFocus required value={value.kind} onChange={e => chooseType(e.target.value)}><option value="" disabled>Choose a type…</option>{Object.entries(types).map(([key, label]) => <option key={key} value={key}>{label}</option>)}</select></label>
      <label className="field">Status<select value={value.status} onChange={e => update('status', e.target.value)}><option>Valid</option><option>Unverified</option><option>Invalid</option></select></label>
      {value.kind === 'domain' && <label className="field">Domain<input required value={value.domain} onChange={e => update('domain', e.target.value)} placeholder="CORP or corp.local" /></label>}
      {needsService && <label className="field">{value.kind === 'other' ? 'Purpose / resource' : 'Service / application'}<input required list="credential-services" value={value.service} onChange={e => update('service', e.target.value)} placeholder="PostgreSQL, web admin, cloud API…" /><datalist id="credential-services"><option>PostgreSQL</option><option>MySQL</option><option>Microsoft SQL Server</option><option>Web application</option><option>FTP</option><option>Cloud API</option></datalist></label>}
      {value.kind && value.kind !== 'domain' && <>
        <label className="field">{needsSystem ? 'System' : 'System (optional)'}<select value={value.host_id || ''} onChange={e => { update('host_id', e.target.value || null); update('system', ''); }}><option value="">Use a hostname or IP…</option>{state.hosts.map(h => <option key={h.id} value={h.id}>{hostName(h)} · {h.address}</option>)}</select></label>
        {!value.host_id && <label className="field">Hostname, IP, or endpoint<input required={needsSystem} value={value.system} onChange={e => update('system', e.target.value)} placeholder={value.kind === 'local' || value.kind === 'ssh' ? 'workstation01 or 192.168.30.10' : 'db01:5432 or https://app.example'} /></label>}
      </>}
      <label className="field">{['api', 'other'].includes(value.kind) ? 'Username / key ID (optional)' : 'Username'}<input required={!!value.kind && !['api', 'other'].includes(value.kind)} value={value.username} onChange={e => update('username', e.target.value)} autoComplete="off" placeholder="Account name" /></label>
      <label className="field">Secret type<select value={value.secret_type} onChange={e => update('secret_type', e.target.value)}>{['Password', 'NTLM hash', 'Token', 'Private key', 'Other'].map(type => <option key={type}>{type}</option>)}</select></label>
      <label className="field credential-secret-field">{value.secret_type}<textarea value={value.secret} onChange={e => update('secret', e.target.value)} rows={value.secret_type === 'Private key' ? 6 : 2} autoComplete="off" spellCheck={false} placeholder={value.secret_type === 'Password' ? 'Leave empty for a blank password' : `Paste ${value.secret_type.toLowerCase()}…`} /></label>
      <label className="field">Found by<select value={value.finder} onChange={e => update('finder', e.target.value)}>{state.users.map(user => <option key={user}>{user}</option>)}</select></label>
    </div>
    <details className="credential-optional-notes" open={notesOpen} onToggle={event => setNotesOpen(event.currentTarget.open)}><summary>Notes <span className="hint">Optional</span><ChevronDown size={15} /></summary>
      <MarkdownEditor label="Credential notes" value={value.notes} onChange={text => update('notes', text)} onBusyChange={setUploading} rows={3} placeholder="Privileges, where it worked, or any limitations…" />
    </details>
    {conflict && <div className="notice">This entry has changed. Your draft is kept. <button type="button" onClick={() => { if (!dirty || window.confirm('Replace your draft with the latest saved credential?')) accept(latest); }}>Load latest version</button></div>}
    {error && <p className="error" role="alert">{error}</p>}
    <div className="row credential-save-row"><button className="primary" disabled={busy || uploading}>{busy ? 'Saving…' : 'Save credential'}</button><span className="hint">{dirty ? 'Draft kept in this tab. Save to share.' : ''}</span></div>
  </form>;
}

function CredentialDialog({ credential, hosts, onClose, onEdit }) {
  const dialog = useRef(null);
  useEffect(() => {
    const node = dialog.current;
    const previous = document.activeElement;
    node.showModal();
    return () => { node.close(); previous?.focus(); };
  }, []);
  return <dialog ref={dialog} className="credential-dialog" aria-labelledby="credential-dialog-title" onCancel={event => { event.preventDefault(); onClose(); }}>
    <div className="row between"><h2 id="credential-dialog-title">Credential details</h2><button autoFocus className="icon-button" onClick={onClose} aria-label="Close credential details"><X /></button></div>
    <dl className="credential-detail-fields">
      <div><dt>Username</dt><dd><code>{credential.username || 'No username'}</code><CopyButton value={credential.username} label="username" /></dd></div>
      <div><dt>{credential.secret_type}</dt><dd><pre>{credential.secret || '(empty password)'}</pre><CopyButton value={credential.secret} label="secret" /></dd></div>
      <div><dt>Used on</dt><dd>{types[credential.kind]} · {scopeText(credential, hosts)}</dd></div>
      <div><dt>Found by</dt><dd>{credential.finder}</dd></div>
      <div><dt>Status</dt><dd>{credential.status}</dd></div>
    </dl>
    {credential.notes && <section><h3>Notes</h3><MarkdownView>{credential.notes}</MarkdownView></section>}
    <div className="row credential-dialog-footer"><button onClick={onEdit}>Edit credential</button><button className="quiet" onClick={onClose}>Close</button></div>
  </dialog>;
}

export default function Credentials({ state, refresh, editId, detailId, onEdit, onDetail }) {
  const editing = editId === 'new' ? 'new' : state.credentials.find(c => c.id === editId) || null;
  const setEditing = value => onEdit(value === 'new' ? 'new' : value?.id);
  const expanded = detailId;
  const setExpanded = onDetail;
  useEscape(() => setEditing(null), !!editing);
  const selectedCredential = (state.credentials || []).find(c => c.id === expanded);
  const [query, setQuery] = useState('');
  const [type, setType] = useState('');
  const [status, setStatus] = useState('');
  const [message, setMessage] = useState('');
  const entries = (state.credentials || []).filter(c => (!type || c.kind === type) && (!status || c.status === status) && [c.username, c.domain, c.service, c.system, scopeText(c, state.hosts), c.notes, c.finder].join(' ').toLowerCase().includes(query.toLowerCase()));
  if (editing) return <main className="credentials-main credential-editor-page"><CredentialForm key={editing.id || 'new'} record={editing === 'new' ? null : editing} state={state} onClose={() => setEditing(null)} onSaved={async () => { await refresh(); setEditing(null); setMessage('Credential saved to the team workspace.'); }} /></main>;
  return <main className="credentials-main">
    <header className="page-header"><h1>Credentials</h1><button className="primary" onClick={() => { setEditing('new'); setMessage(''); }}><Plus /> Add credential</button></header>
    {message && <p className="hint credential-saved" role="status">{message}</p>}

    <div className="toolbar credential-toolbar"><div className="search"><Search /><input aria-label="Search credentials" value={query} onChange={e => setQuery(e.target.value)} placeholder="Search accounts, systems, services…" /></div><select aria-label="Filter credential type" value={type} onChange={e => setType(e.target.value)}><option value="">All types</option>{Object.entries(types).map(([key, label]) => <option key={key} value={key}>{label}</option>)}</select><select aria-label="Filter credential status" value={status} onChange={e => setStatus(e.target.value)}><option value="">All status</option><option>Valid</option><option>Unverified</option><option>Invalid</option></select></div>
    {entries.length ? <div className="table-scroll"><table className="credentials-table"><thead><tr><th>Username</th><th>{entries.every(c => c.secret_type === 'Password') ? 'Password' : 'Secret'}</th><th>Used on</th><th>Found by</th><th><span className="sr-only">Actions</span></th></tr></thead><tbody>{entries.map(c => <tr key={c.id} className={`credential-row ${c.status === 'Valid' ? 'credential-valid' : ''} has-notes`} onClick={event => {
      if (!event.target.closest('button, a, input, summary') && !window.getSelection()?.toString()) { event.currentTarget.querySelector('[aria-haspopup="dialog"]')?.focus(); setExpanded(c.id); }
    }}>
      <td><div className="credential-account"><code>{c.username || 'No username'}</code>{c.username && <CopyButton value={c.username} label="username" />}</div>{c.status !== 'Valid' ? <span className="status">{c.status}</span> : <span className="sr-only">Valid</span>}</td>
      <td>{!entries.every(item => item.secret_type === 'Password') && <span className="hint">{c.secret_type}</span>}<div className="credential-secret"><pre>{c.secret || '(empty)'}</pre><CopyButton value={c.secret} label="secret" /></div></td>
      <td><span className="hint">{types[c.kind]}</span><p className="credential-scope">{scopeText(c, state.hosts)}</p></td>
      <td className="credential-finder">{c.finder}</td><td><div className="credential-actions"><button className="small" onClick={() => { setEditing(c); setMessage(''); window.scrollTo({ top: 0 }); }}>Edit</button><button className="icon-button" aria-label={`View credential for ${c.username || c.service}`} aria-haspopup="dialog" onClick={() => setExpanded(c.id)}><Maximize2 size={16} /></button></div></td>
    </tr>)}</tbody></table></div> : <div className="empty-state"><h2>{state.credentials?.length ? 'No matching credentials' : 'Keep working credentials together'}</h2><p>{state.credentials?.length ? 'Try another search or filter.' : 'Record the account, its secret, and exactly where it works. Everyone on the team can read and copy entries.'}</p>{!editing && <button onClick={() => setEditing('new')}>Add credential</button>}</div>}
    {selectedCredential && <CredentialDialog credential={selectedCredential} hosts={state.hosts} onClose={() => setExpanded(null)} onEdit={() => setEditing(selectedCredential)} />}
  </main>;
}
