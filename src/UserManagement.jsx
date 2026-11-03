import { useState } from 'react';
import { ArrowLeft, Download } from 'lucide-react';
import { api } from './api';
import useEscape from './useEscape';
import RestoreBackup from './RestoreBackup';

export default function UserManagement({ state, refresh, onBack }) {
  const [backupBusy, setBackupBusy] = useState(false);
  const [username, setUsername] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [message, setMessage] = useState('');
  const [removing, setRemoving] = useState(null);
  useEscape(onBack);
  async function update(name, remove = false) {
    setBusy(true); setError(''); setMessage('');
    try {
      await api(remove ? `/admin/users/${encodeURIComponent(name)}` : '/admin/users', { method: remove ? 'DELETE' : 'POST', ...(remove ? {} : { json: { username: name } }) });
      await refresh(); setUsername(''); setRemoving(null); setMessage(`${name} ${remove ? 'removed' : 'authorized'}.`);
    } catch (err) { setError(err.message); }
    finally { setBusy(false); }
  }
  async function downloadBackup() {
    setBackupBusy(true); setError(''); setMessage('');
    try {
      const collect = storage => Object.fromEntries(Object.keys(storage).filter(key => key.startsWith('kiss:')).map(key => [key, storage.getItem(key)]));
      let browserState = { session: {}, local: {} };
      try { browserState = { session: collect(sessionStorage), local: collect(localStorage) }; } catch { /* Browser storage may be disabled. */ }
      const response = await fetch('/api/admin/backup', { method: 'POST', credentials: 'same-origin', headers: { 'X-Kiss-Request': '1', 'Content-Type': 'application/json' }, body: JSON.stringify(browserState) });
      if (!response.ok) { const error = await response.json().catch(() => ({})); throw new Error(error.detail || 'Backup download failed.'); }
      const blob = await response.blob();
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url; link.download = response.headers.get('Content-Disposition')?.match(/filename="([^"]+)"/)?.[1] || 'kiss-backup.zip';
      document.body.append(link); link.click(); link.remove();
      setTimeout(() => URL.revokeObjectURL(url), 60000);
      setMessage('Backup generated. Check your browser downloads. Restore instructions are inside the ZIP.');
    } catch (err) { setError(err.message); }
    finally { setBackupBusy(false); }
  }
  return <main className="users-page">
    <button className="quiet back-link" onClick={onBack}><ArrowLeft size={16} /> Home</button>
    <header className="page-header"><h1>Team settings</h1></header>
    {!state.is_admin ? <p>Only the configured admin can manage authorized users.</p> : <>
      <h2>Authorized users</h2>
      <form className="user-add-form" onSubmit={event => { event.preventDefault(); void update(username.trim()); }}>
        <label className="field">Username<input required maxLength={64} pattern="[A-Za-z0-9][A-Za-z0-9_.\-]{0,63}" value={username} onChange={event => setUsername(event.target.value)} placeholder="Teammate’s username" autoComplete="off" /></label>
        <button className="primary" disabled={busy}>Add user</button>
      </form>
      {error && <p className="error" role="alert">{error}</p>}{message && <p className="hint" role="status">{message}</p>}
      <ul className="user-list">{state.users.map(user => <li key={user}><span>{user}</span>{user === state.admin_username ? <span className="hint">Admin · set in config</span> : removing === user ? <div className="row"><span className="hint">Revoke access?</span><button disabled={busy} onClick={() => update(user, true)}>Remove</button><button className="quiet" onClick={() => setRemoving(null)}>Keep</button></div> : <button className="quiet small" disabled={busy} onClick={() => setRemoving(user)}>Remove</button>}</li>)}</ul>
      <p className="hint">Removing a user revokes their sessions. Their existing work stays in the workspace.</p>
      <section className="backup-section" aria-labelledby="backup-title"><h2 id="backup-title">Full workspace backup</h2><p className="muted">Database, credentials, evidence, users, configuration, app files, and drafts from this browser tab.</p><button disabled={backupBusy} onClick={downloadBackup}><Download size={16} />{backupBusy ? 'Preparing backup…' : 'Download backup ZIP'}</button><p className="hint">Includes restore instructions. Other teammates’ unsaved drafts and installed system tools aren’t included.</p></section>
      <RestoreBackup admin={state.admin_username} />
    </>}
  </main>;
}
