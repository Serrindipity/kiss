import { useRef, useState } from 'react';
import { Upload } from 'lucide-react';
import { api } from './api';

export default function RestoreBackup({ admin }) {
  const input = useRef(null);
  const [file, setFile] = useState(null);
  const [preview, setPreview] = useState(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [result, setResult] = useState(null);

  async function inspect(selected) {
    setFile(null); setPreview(null); setError('');
    if (!selected) return;
    if (selected.size > 256 * 1024 * 1024) { setError('Choose a ZIP smaller than 256 MB.'); return; }
    setBusy(true);
    try {
      const details = await api('/admin/restore', { method: 'POST', body: selected });
      setFile(selected); setPreview(details);
    } catch (err) { setError(err.message); }
    finally { setBusy(false); }
  }

  async function restore() {
    setBusy(true); setError('');
    try {
      const restored = await api('/admin/restore', { method: 'POST', body: file, headers: { 'X-Kiss-Restore-Confirm': preview.sha256 } });
      setResult(restored); setPreview(null); setFile(null);
      // Old local drafts must not overwrite newly restored shared records.
      try { Object.keys(sessionStorage).filter(key => key.startsWith('kiss:')).forEach(key => sessionStorage.removeItem(key)); } catch { /* Storage can be disabled. */ }
    } catch (err) { setError(err.message); }
    finally { setBusy(false); }
  }

  return <section className="backup-section" aria-labelledby="restore-title" aria-busy={busy}>
    <h2 id="restore-title">Restore workspace</h2>
    {result ? <>
      <p role="status">Workspace restored. Sign in again as {result.admin_username} or an authorized teammate.</p>
      <p className="hint">Previous workspace saved on the server: data/{result.recovery_file}</p>
      <button className="primary" onClick={() => window.location.assign('/home')}>Sign in again</button>
    </> : <>
      <p className="muted">Upload a KISS backup ZIP to replace shared data, evidence, and authorized users. You’ll review it before restoring.</p>
      <input ref={input} type="file" accept=".zip,application/zip" hidden onChange={event => { void inspect(event.target.files?.[0]); event.target.value = ''; }} />
      <button disabled={busy} onClick={() => input.current.click()}><Upload size={16} />{busy ? (preview ? 'Restoring…' : 'Checking backup…') : 'Upload backup ZIP'}</button>
      {preview && <div className="restore-review">
        <h3>Replace this workspace?</h3>
        <p className="restore-filename">{file.name}</p>
        <p>{preview.counts.hosts || 0} hosts · {preview.counts.findings || 0} findings · {preview.counts.credentials || 0} credentials · {preview.evidence} evidence files</p>
        <p className="hint">Includes networks, activity, scan history, automation runs, and {preview.users.length} authorized users. {admin} stays the admin. App files and server settings stay as they are.</p>
        <p>A recovery ZIP is saved first. Everyone will be signed out, and this tab’s unsaved drafts will be cleared. Finish or cancel running jobs before continuing.</p>
        <div className="row"><button className="danger" disabled={busy} onClick={restore}>Replace workspace</button><button disabled={busy} onClick={() => { setPreview(null); setFile(null); setError(''); }}>Cancel</button></div>
      </div>}
    </>}
    {error && <p className="error" role="alert">{error}</p>}
  </section>;
}
