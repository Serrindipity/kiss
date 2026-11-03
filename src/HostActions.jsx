import { useEffect, useLayoutEffect, useRef, useState } from 'react';
import { createPortal } from 'react-dom';
import { Pencil, Trash2, X } from 'lucide-react';
import { api, hostName } from './api';

export default function HostActions({ target, onClose, onChanged }) {
  const [portalRoot] = useState(() => document.createElement('div'));
  useLayoutEffect(() => {
    document.body.append(portalRoot);
    return () => portalRoot.remove();
  }, [portalRoot]);
  const menu = useRef(null);
  const dialog = useRef(null);
  const [mode, setMode] = useState(null);
  const [hostname, setHostname] = useState(target.host.hostname || '');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const host = target.host;
  useLayoutEffect(() => {
    if (mode) return;
    const node = menu.current;
    const rect = node.getBoundingClientRect();
    node.style.left = `${Math.max(8, Math.min(target.x, window.innerWidth - rect.width - 8))}px`;
    node.style.top = `${Math.max(8, Math.min(target.y, window.innerHeight - rect.height - 8))}px`;
    node.querySelector('button')?.focus({ preventScroll: true });
    const dismiss = event => { if (event.button !== 2 && !node.contains(event.target)) onClose(false); };
    const context = event => { if (!node.contains(event.target)) onClose(false); };
    const reposition = () => onClose(false);
    const escape = event => { if (event.key === 'Escape') { event.preventDefault(); event.stopPropagation(); onClose(); } };
    document.addEventListener('pointerdown', dismiss);
    document.addEventListener('keydown', escape, true);
    document.addEventListener('contextmenu', context);
    window.addEventListener('resize', reposition);
    document.addEventListener('scroll', reposition, true);
    return () => {
      document.removeEventListener('pointerdown', dismiss);
      document.removeEventListener('keydown', escape, true);
      document.removeEventListener('contextmenu', context);
      window.removeEventListener('resize', reposition);
      document.removeEventListener('scroll', reposition, true);
    };
  }, [mode, target, onClose]);
  useEffect(() => {
    if (!mode) return;
    const node = dialog.current;
    node.showModal();
    return () => node.close();
  }, [mode]);
  async function save(event) {
    event.preventDefault(); setBusy(true); setError('');
    try {
      await api(mode === 'delete' ? `/hosts/${host.id}?revision=${host.revision}` : `/hosts/${host.id}/hostname`,
        mode === 'delete' ? { method: 'DELETE' } : { method: 'PUT', json: { hostname, revision: host.revision } });
      await onChanged(host.id, mode === 'delete');
      onClose();
    } catch (err) { setError(err.message); }
    finally { setBusy(false); }
  }
  return createPortal(mode ? <dialog className="host-action-dialog" ref={dialog} aria-labelledby="host-action-title" onCancel={event => { event.preventDefault(); onClose(); }}>
    <form onSubmit={save}><div className="row between"><h2 id="host-action-title">{mode === 'delete' ? 'Delete host' : 'Edit hostname'}</h2><button type="button" className="icon-button" onClick={onClose} aria-label="Close host action"><X size={18} /></button></div>
      <p className="muted">{hostName(host)} · {host.address}</p>
      {mode === 'rename' ? <label className="field">Hostname<input autoFocus maxLength={253} value={hostname} onChange={event => setHostname(event.target.value)} placeholder={host.address} /><span className="hint">Leave empty to display the IP address.</span></label> : <p>Remove this host and its notes from the workspace? Original scan files are kept. A later discovery or scan import may add it again.</p>}
      {error && <p className="error" role="alert">{error}</p>}
      <div className="row"><button className={mode === 'delete' ? 'host-delete-button' : 'primary'} disabled={busy}>{busy ? 'Saving…' : mode === 'delete' ? 'Delete host' : 'Save hostname'}</button><button type="button" onClick={onClose}>Cancel</button></div>
    </form>
  </dialog> : <div ref={menu} role="menu" aria-label={`Actions for ${hostName(host)}`} className="host-context-menu" onContextMenu={event => { event.preventDefault(); event.stopPropagation(); }} style={{ left: target.x, top: target.y }} onKeyDown={event => {
    if (['ArrowDown', 'ArrowUp', 'Home', 'End'].includes(event.key)) {
      event.preventDefault(); const items = [...menu.current.querySelectorAll('button')]; const index = items.indexOf(document.activeElement);
      items[event.key === 'Home' ? 0 : event.key === 'End' ? items.length - 1 : (index + (event.key === 'ArrowDown' ? 1 : -1) + items.length) % items.length]?.focus();
    } else if (event.key === 'Tab') onClose();
  }}><button role="menuitem" onClick={() => setMode('rename')}><Pencil size={15} /> Edit hostname</button><button role="menuitem" onClick={() => setMode('delete')}><Trash2 size={15} /> Delete host</button></div>, portalRoot);
}
