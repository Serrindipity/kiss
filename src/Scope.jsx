import { useCallback, useEffect, useRef, useState } from 'react';
import { CheckCircle2, Clock3, CircleAlert, MoreHorizontal, ChevronDown, Plus, Search, Upload, X, ArrowLeft } from 'lucide-react';
import { api, displayTime, hostName, openPorts, portName } from './api';
import MarkdownEditor from './MarkdownEditor';
import useDraft from './useDraft';
import useEscape from './useEscape';
import usePanelResize from './usePanelResize';
import { relativeTime } from './activity';
import NetworkDns, { DnsFields } from './NetworkDns';
import DiscoveryStatus from './DiscoveryStatus';
import HostActions from './HostActions';
import ScanViewer from './ScanViewer';

const hasPortScan = host => Boolean(host.port_scanned_at || host.ports?.length || host.port_scan?.status === 'Complete');

const statuses = ['Unreviewed', 'Investigating', 'Reviewed'];

export function BatchForm({ networks, selectedNetwork, onDone, onClose }) {
  const [kind, setKind] = useState('network');
  const [text, setText] = useState('');
  const [network, setNetwork] = useState(networks.some(n => n.id === selectedNetwork) ? selectedNetwork : '');
  const [discover, setDiscover] = useState(true);
  const [dnsServer, setDnsServer] = useState('');
  const [dnsZone, setDnsZone] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  async function submit(event) {
    event.preventDefault(); setBusy(true); setError('');
    try {
      const result = await api('/scope', { method: 'POST', json: { kind, text, discover, dns_server: kind === 'network' ? dnsServer : '', dns_zone: kind === 'network' ? dnsZone : '', network_id: kind === 'host' ? network || null : null } });
      onDone(result.added ? `Added ${result.added} scope item${result.added === 1 ? '' : 's'}.` : 'Already in scope. Existing entries were kept.');
    } catch (err) { setError(err.message); }
    finally { setBusy(false); }
  }
  return <form className="inline-form" onSubmit={submit}>
    <div className="row between"><h2>Add scope</h2><button type="button" className="icon-button" onClick={onClose} aria-label="Close add scope"><X /></button></div>
    <div className="row wrap"><label className="field">Type<select value={kind} onChange={e => setKind(e.target.value)}><option value="network">Networks</option><option value="host">Hosts</option><option value="cloud">Cloud hosts</option></select></label>
      {kind === 'host' && <label className="field">Network<select value={network} onChange={e => setNetwork(e.target.value)}><option value="">Match by subnet</option>{networks.map(n => <option key={n.id} value={n.id}>{n.name} · {n.cidr}</option>)}</select></label>}
    </div>
    <label className="field">{kind === 'network' ? 'Subnets, one per line' : 'IP addresses or hostnames, one per line'}
      <textarea autoFocus value={text} onChange={e => setText(e.target.value)} required rows={5} placeholder={kind === 'network' ? '10.20.0.0/24 Corporate\n10.30.0.0/24 Lab' : '10.20.0.10 dc01.corp.local\napp.example.test'} />
    </label>
    <p className="hint">Add an optional name after each address. Commas or spaces work.</p>
    {kind === 'network' && <><DnsFields server={dnsServer} zone={dnsZone} setServer={setDnsServer} setZone={setDnsZone} /><label className="check"><input type="checkbox" checked={discover} onChange={e => setDiscover(e.target.checked)} /> Discover hosts after adding networks</label><p className="hint">Runs a host-only sweep from this server. No port scan. IPv4 subnets up to 4,096 addresses by default.</p></>}
    {error && <p role="alert" className="error">{error}</p>}
    <button className="primary" disabled={busy}>{busy ? 'Adding…' : 'Add to scope'}</button>
  </form>;
}

function PortEvidence({ port }) {
  return <div className="port-evidence port-compact">
    <code>{portName(port)}</code>
    <div><span>{port.tunnel ? `${port.tunnel}/` : ''}{port.service}</span>{(port.product || port.version) && <p className="hint">{[port.product, port.version].filter(Boolean).join(' ')}</p>}{port.state !== 'open' && <span className="hint">{port.state}</span>}</div>
  </div>;
}

function HostDetail({ host, username, users, onSaved, onFinding, onClose, onViewScan }) {
  const heading = useRef(null);
  useEffect(() => {
    if (window.matchMedia('(max-width: 1099px)').matches) {
      heading.current?.focus();
      window.scrollTo(0, 0);
    }
  }, []);
  const initial = { notes: host.notes, status: host.status, owner: host.owner || '', revision: host.revision };
  const { value, setValue, dirty, accept } = useDraft(`kiss:${username}:host:${host.id}`, initial);
  const [busy, setBusy] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');
  const [allPorts, setAllPorts] = useState(false);
  const [scanBusy, setScanBusy] = useState(false);
  const [scanError, setScanError] = useState('');
  const scanning = ['Queued', 'Running'].includes(host.port_scan?.status);
  const scanned = hasPortScan(host);
  const scanFailed = ['Failed', 'Interrupted', 'Cancelled', 'Not started'].includes(host.port_scan?.status);
  const lastPortScan = host.port_scanned_at || (host.port_scan?.status === 'Complete' ? host.port_scan.finished_at : null) || host.ports.map(port => port.scanned_at).filter(Boolean).sort().at(-1);
  const latestScanId = host.port_scan_id || [...host.ports].filter(port => port.scan_id).sort((a, b) => (b.scanned_at || '').localeCompare(a.scanned_at || ''))[0]?.scan_id;
  const confirmedOpen = host.ports.filter(port => port.state === 'open').length;
  const uncertainOpen = host.ports.filter(port => port.state === 'open|filtered').length;
  async function scanPorts(cancel = false) {
    setScanBusy(true); setScanError('');
    try {
      await api(`/hosts/${host.id}/scan${cancel ? '/cancel' : ''}`, { method: 'POST' });
      await onSaved();
    } catch (err) { setScanError(err.message); }
    finally { setScanBusy(false); }
  }
  const ports = allPorts ? host.ports : openPorts(host);
  const groups = Object.groupBy(ports, p => p.group);
  const changed = value.revision !== host.revision;
  function update(field, next) { setValue(old => ({ ...old, [field]: next })); setMessage(''); }
  async function save() {
    setBusy(true); setError('');
    try {
      const saved = await api(`/hosts/${host.id}`, { method: 'PUT', json: value });
      accept({ notes: saved.notes, status: saved.status, owner: saved.owner || '', revision: saved.revision });
      onSaved(); setMessage('Saved to team workspace.');
    } catch (err) { setError(err.message); }
    finally { setBusy(false); }
  }
  return <aside id="host-detail" className="host-detail" aria-label="Host details" tabIndex={0}>
    <button className="quiet back-detail" onClick={onClose}><ArrowLeft size={16} /> Back to hosts</button>
    <div className="detail-title"><div><h2 ref={heading} tabIndex={-1}>{hostName(host)}</h2><p className="address">{host.address}</p></div><button className="primary" onClick={() => onFinding(host)}>New finding</button></div>
    {host.os && <p className="hint" title={`${host.os.source}${host.os.evidence ? ` · Build ${host.os.evidence}` : ''}`}>{host.os.name} · {host.os.method === 'reported' ? 'Reported OS' : host.os.method === 'fingerprint' ? `Nmap fingerprint (${host.os.accuracy}%)` : 'Inferred OS'}</p>}
    {!!host.aliases?.length && <p className="hint host-aliases">Also known as: {host.aliases.join(', ')}</p>}
    {host.dns_source && <p className="hint">DNS zone: {host.dns_source.zone} · <button className="quiet small" aria-haspopup="dialog" onClick={() => onViewScan(host.dns_source.scan_id, `DNS discovery · ${hostName(host)}`)}>View evidence</button></p>}
    <div className="host-assignment"><label className="field">Owner<select value={value.owner || ''} onChange={e => update('owner', e.target.value)}><option value="">Unassigned</option>{users.map(user => <option key={user}>{user}</option>)}</select></label><button className="small" disabled={value.owner === username} onClick={() => update('owner', username)}>Assign to me</button></div>
    <label className="field">Status<select value={value.status} onChange={e => update('status', e.target.value)}>{statuses.map(s => <option key={s}>{s}</option>)}</select></label>
    <p className="hint">{host.scanned_at ? `Last observation ${displayTime(host.scanned_at)} · ${host.reachability}` : 'No scan imported yet.'}</p>
    {changed && <div className="notice"><p>A teammate or scan updated this host. Your draft is kept.</p><button className="small" onClick={() => { if (!dirty || window.confirm('Replace your local draft with the latest server version?')) { accept(initial); setError(''); } }}>Load latest version</button></div>}
    <section className="host-scan-controls ports-section" aria-label="Ports and services">
      <div className="ports-heading-row"><h3>Ports &amp; services</h3>
      <div className="port-scan-summary" role="status">
        <span className={`scan-state ${scanning ? 'scan-state-active' : scanFailed ? 'scan-state-incomplete' : scanned ? 'scan-state-complete' : ''}`}>
          {scanning ? <Clock3 size={15} /> : scanFailed ? <CircleAlert size={15} /> : scanned ? <CheckCircle2 size={15} /> : null}
          {scanning ? (host.port_scan.status === 'Queued' ? 'Queued' : 'Scanning') : scanFailed ? host.port_scan.status : scanned ? 'Scanned' : 'Not yet scanned'}
        </span>
        {scanned && <span className="hint">{confirmedOpen} open {confirmedOpen === 1 ? 'port' : 'ports'}{uncertainOpen > 0 && ` · ${uncertainOpen} open or filtered`}</span>}
      {scanning && <p className="scan-progress hint" role="status">{host.port_scan.status === 'Running' ? (host.port_scan.phase || 'Starting scan…') : 'Waiting for a scan slot'}{host.port_scan.status === 'Running' && Number.isFinite(host.port_scan.percent) && <> · {host.port_scan.percent}% of this phase</>}</p>}
      </div>
        {scanning ? <button className="small" disabled={scanBusy} onClick={() => scanPorts(true)}>Cancel scan</button> : <button className="small" disabled={scanBusy} onClick={() => scanPorts()}>{scanBusy ? 'Starting…' : scanned ? 'Scan again' : 'Scan ports'}</button>}
      </div>
      {(lastPortScan || latestScanId) && <div className="port-scan-meta">{lastPortScan && <span className="hint">{scanning || scanFailed ? 'Previous scan' : 'Scanned'}  <time tabIndex={0} title={displayTime(lastPortScan)} aria-label={displayTime(lastPortScan)}>{relativeTime(typeof lastPortScan === 'number' ? lastPortScan : new Date(lastPortScan).getTime() / 1000)}</time></span>}{latestScanId && <button className="quiet small" aria-haspopup="dialog" onClick={() => onViewScan(latestScanId, hostName(host))}>View scan</button>}</div>}
      {scanError && <p className="error" role="alert">{scanError}</p>}

      {scanFailed && <p className={host.port_scan.status === 'Failed' ? 'error' : 'hint'}>{host.port_scan.message}</p>}
      {scanned && <div className="ports-simple-filter"><label className="check hint"><input type="checkbox" checked={allPorts} onChange={e => setAllPorts(e.target.checked)} /> Include closed / filtered</label></div>}
      {ports.length ? <div className="service-groups">{Object.entries(groups).map(([group, items]) => <details className="service-group" key={group}>
        <summary><span>{group}</span><span className="hint">{items.length} {items.length === 1 ? 'port' : 'ports'}</span><ChevronDown size={16} /></summary>
        <div className="group-content">{items.map(port => <PortEvidence key={portName(port)} port={port} />)}</div>
      </details>)}</div> : <p className="muted">{scanned ? (allPorts ? 'No individual ports recorded in this scan.' : 'No open ports recorded.') : (scanning ? 'Results will appear here when the scan finishes.' : 'Scan this host or import Nmap XML to see its services.')}</p>}

    </section>
    <div className="detail-section"><MarkdownEditor label="Notes" value={value.notes} onChange={text => update('notes', text)} onBusyChange={setUploading} placeholder="What have you checked? Paste commands, evidence, or screenshots…" rows={9} />
      <div className="row"><button className="primary" disabled={busy || uploading || !dirty} onClick={save}>{busy ? 'Saving…' : 'Save host'}</button><span className="hint" role="status">{message || (dirty ? 'Unsaved changes' : '')}</span></div>
      {error && <p role="alert" className="error">{error}</p>}
    </div>
  </aside>;
}

export default function Scope({ state, network, refresh, onFinding, selected, setSelected }) {
  const panel = usePanelResize();
  const [viewingScan, setViewingScan] = useState(null);
  const viewScan = (id, title) => setViewingScan({ id, title });
  const [contextTarget, setContextTarget] = useState(null);
  const menuTrigger = useRef(null);
  const menuSequence = useRef(0);
  function openHostMenu(event, host) {
    event.preventDefault(); event.stopPropagation();
    const trigger = event.currentTarget.querySelector('.host-menu-trigger') || event.currentTarget;
    menuTrigger.current = trigger;
    const rect = trigger.getBoundingClientRect();
    setContextTarget({ key: ++menuSequence.current, host, x: event.type === 'contextmenu' && event.clientX ? event.clientX : rect.left, y: event.type === 'contextmenu' && event.clientY ? event.clientY : rect.bottom });
  }
  const closeHostMenu = useCallback((restoreFocus = true) => {
    setContextTarget(null);
    if (restoreFocus) menuTrigger.current?.focus({ preventScroll: true });
  }, []);

  const [query, setQuery] = useState('');
  const [owner, setOwner] = useState('');
  const [adding, setAdding] = useState(false);
  useEscape(() => { setAdding(false); setSelected(null); document.querySelectorAll('#workspace details[open]').forEach(node => { node.open = false; }); });
  const [importing, setImporting] = useState(false);
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');
  const importInput = useRef(null);
  const hosts = state.hosts.filter(host => {
    const inNetwork = network === 'all' || (network === 'cloud' ? host.cloud : network === 'unassigned' ? !host.network_id && !host.cloud : host.network_id === network);
    const matches = [host.hostname, host.address, ...(host.aliases || []), ...host.ports.map(p => `${p.service} ${p.group} ${p.port} ${p.product}`)].join(' ').toLowerCase().includes(query.toLowerCase());
    return inNetwork && matches && (!owner || (owner === '__unassigned' ? !host.owner : host.owner === owner));
  });
  const host = hosts.find(h => h.id === selected);
  const discoveryNetworks = state.networks.filter(n => n.discovery && network === 'all');
  async function retryDiscovery(id) {
    try { await api(`/networks/${id}/discover`, { method: 'POST' }); refresh(); }
    catch (err) { setError(err.message); }
  }
  const networkTitle = state.networks.find(n => n.id === network);
  async function importFiles(files) {
    if (!files.length) return;
    setImporting(true); setMessage(''); setError('');
    let imported = 0, duplicates = 0;
    try {
      for (const file of files) {
        if (file.size > 20 * 1024 * 1024) throw new Error(`${file.name} exceeds the 20 MB scan limit.`);
        const result = await api('/import', { method: 'POST', body: file });
        if (result.duplicate) duplicates++; else imported++;
      }
      setMessage(`${imported} scan${imported === 1 ? '' : 's'} imported${duplicates ? `; ${duplicates} duplicate${duplicates === 1 ? '' : 's'} skipped` : ''}.`);
    } catch (err) { setError(`${err.message}${imported ? ` ${imported} earlier scans were imported.` : ''}`); }
    finally { refresh(); setImporting(false); }
  }
  return <div ref={panel.container} style={{ '--host-panel-width': `${panel.width}px` }} className={`scope-layout ${host ? 'with-detail' : ''} ${panel.dragging ? 'resizing' : ''}`}>
    <main className="scope-main" tabIndex={0} aria-label="Hosts overview">
      <header className="page-header"><div className="page-heading"><h1>{networkTitle?.name || (network === 'cloud' ? 'Cloud hosts' : network === 'unassigned' ? 'Unassigned hosts' : 'Scope')}</h1>{networkTitle && <p className="page-subtitle">{networkTitle.cidr}</p>}</div><div className="row"><button disabled={importing} onClick={() => importInput.current.click()}><Upload />{importing ? 'Importing…' : 'Import scan'}</button><button className="primary" onClick={() => setAdding(v => !v)}><Plus /> Add scope</button></div></header>
      <input ref={importInput} type="file" accept=".xml,text/xml,application/xml" multiple hidden aria-label="Nmap XML files" onChange={e => { void importFiles([...e.target.files]); e.target.value = ''; }} />
      <div hidden={!adding}><BatchForm networks={state.networks} selectedNetwork={network} onClose={() => setAdding(false)} onDone={text => { setMessage(text); setAdding(false); refresh(); }} /></div>
      {message && <div className="feedback"><p role="status">{message}</p><button className="icon-button" aria-label="Dismiss notice" onClick={() => setMessage('')}><X size={16} /></button></div>}{error && <p role="alert" className="error">{error}</p>}
      {networkTitle && <NetworkDns key={networkTitle.id} network={networkTitle} refresh={refresh} />}
      <div className="toolbar"><div className="search"><Search /><input aria-label="Search hosts" placeholder="Search hosts, addresses, services…" value={query} onChange={e => setQuery(e.target.value)} /></div><select aria-label="Filter host owner" value={owner} onChange={e => setOwner(e.target.value)}><option value="">All owners</option><option value="__unassigned">Unassigned</option>{state.users.map(user => <option key={user}>{user}</option>)}</select></div>
      {hosts.length ? <div className="table-scroll"><table className="host-table"><thead><tr><th>Host</th><th>Address</th><th>Services</th><th>Owner</th></tr></thead><tbody>{hosts.map(h => <tr key={h.id} onContextMenu={event => openHostMenu(event, h)} onKeyDown={event => { if ((event.shiftKey && event.key === 'F10') || event.key === 'ContextMenu') openHostMenu(event, h); }} className={h.id === selected ? 'selected' : ''} onClick={() => setSelected(h.id)}>
        <td><div className="host-name-actions"><button className="table-link" aria-pressed={h.id === selected} onClick={() => setSelected(h.id)}>{hostName(h)}</button><button className="icon-button host-menu-trigger" aria-label={`Actions for ${hostName(h)}`} aria-haspopup="menu" onClick={event => openHostMenu(event, h)}><MoreHorizontal size={16} /></button></div></td><td><code>{h.address}</code></td><td className="service-summary">{[...new Set(openPorts(h).map(p => p.group.replace('Directory services', 'Directory').replace('Microsoft RPC', 'RPC').replace('Other / unidentified', 'Other')))].join(' · ') || <span className="muted">{hasPortScan(h) ? 'No open ports' : 'Not yet scanned'}</span>}</td><td><span title={h.owner || 'Unassigned'} className={`owner-badge owner-${h.owner ? state.users.indexOf(h.owner) % 6 : 'none'}`}>{h.owner || 'Unassigned'}</span></td>
      </tr>)}</tbody></table></div> : <div className="empty-state"><h2>{state.hosts.length ? 'No matching hosts' : 'Start with your scope'}</h2><p>{state.hosts.length ? 'Try another search or network filter.' : 'Add the assigned subnets, then import your Nmap discovery and service scans. Your team’s hosts and evidence will appear here.'}</p>{!state.hosts.length && <button onClick={() => setAdding(true)}>Add networks or hosts</button>}</div>}
      <div className="table-caption">{hosts.length} {hosts.length === 1 ? 'host' : 'hosts'}{host ? ' · Select a host to review evidence' : ''}</div>
      {!!discoveryNetworks.length && <section className="discovery-list" aria-label="Host discovery"><h3>Host discovery</h3>{discoveryNetworks.map(n => <div className="discovery-row" key={n.id}><div><strong>{n.name}</strong><DiscoveryStatus discovery={n.discovery} /></div><button className="small" disabled={['Running', 'Queued'].includes(n.discovery.status)} onClick={() => retryDiscovery(n.id)}>{n.discovery.status === 'Complete' ? 'Sweep again' : 'Retry'}</button></div>)}</section>}
      <details className="scan-history"><summary>Scan imports <span className="hint">{state.scans.length}</span><ChevronDown size={16} /></summary>
        {!state.scans.length && <p className="hint">Save Nmap output with <code>-oX scan.xml</code>, then import the XML here. Discovery scans work too.</p>}
        {state.scans.toReversed().map(scan => <div className="scan-row" key={scan.id}><div>{displayTime(scan.scanned_at)}<span className="hint">{scan.source ? `${scan.source} · ` : ''}{scan.hosts} hosts · imported by {scan.finder}</span></div><button className="small" aria-haspopup="dialog" onClick={() => viewScan(scan.id, `${scan.source || 'Imported scan'} · ${displayTime(scan.scanned_at)}`)}>View scan</button></div>)}
      </details>
    </main>
    {contextTarget && <HostActions key={contextTarget.key} target={contextTarget} onClose={closeHostMenu} onChanged={async (id, deleted) => { if (deleted && selected === id) setSelected(null); await refresh(); }} />}
    {host && <div className="scope-divider" {...panel.separator} title="Drag to resize · Arrow keys to adjust · Double-click to reset" />}
    {host && <HostDetail key={host.id} host={host} username={state.username} users={state.users} onSaved={refresh} onFinding={onFinding} onViewScan={viewScan} onClose={() => setSelected(null)} />}
    {viewingScan && <ScanViewer key={viewingScan.id} scanId={viewingScan.id} title={viewingScan.title} onClose={() => setViewingScan(null)} />}
  </div>;
}
