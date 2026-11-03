import { useState } from 'react';
import { ChevronDown } from 'lucide-react';
import { api } from './api';
import DiscoveryStatus from './DiscoveryStatus';

export function DnsFields({ server, zone, setServer, setZone }) {
  return <div className="dns-fields">
    <label className="field">DNS server IP<input value={server} onChange={e => setServer(e.target.value)} placeholder="10.20.0.10" maxLength={64} /></label>
    <label className="field">DNS zone<input value={zone} onChange={e => setZone(e.target.value)} placeholder="corp.local" maxLength={253} /></label>
    <details className="dns-help"><summary>How DNS is used <ChevronDown size={13} /></summary><p className="hint">Both fields are optional. The server resolves hostnames; the zone is the domain to request records for. Discovery tries a zone transfer first, then reverse DNS if unavailable. Settings apply only to this network.</p></details>
  </div>;
}

export default function NetworkDns({ network, refresh }) {
  const [server, setServer] = useState(network.dns_server || '');
  const [zone, setZone] = useState(network.dns_zone || '');
  const [error, setError] = useState('');
  const [message, setMessage] = useState('');
  const [busy, setBusy] = useState('');
  const running = ['Queued', 'Running'].includes(network.discovery?.status);
  const dirty = server !== (network.dns_server || '') || zone !== (network.dns_zone || '');
  async function save(event) {
    event.preventDefault(); setBusy('save'); setError(''); setMessage('');
    try {
      const saved = await api(`/networks/${network.id}/dns`, { method: 'PUT', json: { dns_server: server, dns_zone: zone } });
      setServer(saved.dns_server); setZone(saved.dns_zone);
      await refresh();
      setMessage(`DNS settings saved for ${network.name}.`);
    } catch (err) { setError(err.message); }
    finally { setBusy(''); }
  }
  async function discover() {
    setBusy('discover'); setError(''); setMessage('');
    try { await api(`/networks/${network.id}/discover`, { method: 'POST' }); await refresh(); }
    catch (err) { setError(err.message); }
    finally { setBusy(''); }
  }
  return <section className="network-settings" aria-label={`DNS and discovery for ${network.name}`}>
    <details className="network-dns"><summary aria-label={`Edit DNS for ${network.name}`}>
      <span className="dns-summary"><span className="dns-summary-title">DNS for {network.name}</span><span className="hint">{network.dns_server || 'Not configured'}{network.dns_zone ? ` · ${network.dns_zone}` : ''}</span></span>
      <span className="dns-edit-label"><span className="when-closed">{network.dns_server ? 'Edit' : 'Configure'}</span><span className="when-open">Close</span><ChevronDown size={16} /></span>
    </summary>
      <form onSubmit={save}>
        <DnsFields server={server} zone={zone} setServer={setServer} setZone={setZone} />
        <div className="row wrap">{(dirty || busy === 'save') && <button disabled={!!busy || running}>{busy === 'save' ? 'Saving…' : 'Save DNS settings'}</button>}{running && dirty && <span className="hint">Wait for discovery to finish before saving.</span>}</div>
      </form>
    </details>
    <div className="network-discovery-actions"><button disabled={!!busy || running || dirty} onClick={discover}>{busy === 'discover' ? 'Starting…' : running ? 'Discovering…' : 'Discover hosts'}</button>
      <div>{dirty ? <span className="hint">Save changes first.</span> : <DiscoveryStatus discovery={network.discovery} />}</div>
    </div>
    {message && <p className="hint settings-feedback" role="status">{message}</p>}
    {error && <p className="error" role="alert">{error}</p>}
  </section>;
}
