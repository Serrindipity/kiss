import { useEffect, useMemo, useRef, useState } from 'react';
import { createPortal } from 'react-dom';
import { ChevronLeft, ChevronRight, Copy, Download, Search, X } from 'lucide-react';
import { highlightScanLine, scanLineKind, SCAN_PAGE_SIZE } from './scanViewer';
import './scanViewer.css';

export default function ScanViewer({ scanId, title, onClose }) {
  const dialog = useRef(null);
  const currentLine = useRef(null);
  const [text, setText] = useState(null);
  const [error, setError] = useState('');
  const [retry, setRetry] = useState(0);
  const [query, setQuery] = useState('');
  const [matchIndex, setMatchIndex] = useState(0);
  const [manualPage, setManualPage] = useState(0);
  const [wrap, setWrap] = useState(true);
  const [notice, setNotice] = useState('');
  useEffect(() => {
    const node = dialog.current, previous = document.activeElement;
    node.showModal();
    return () => { node.close(); if (previous?.isConnected) previous.focus({ preventScroll: true }); };
  }, []);
  useEffect(() => {
    const controller = new AbortController();
    setText(null); setError('');
    async function load() {
      try {
        const response = await fetch(`/api/scans/${encodeURIComponent(scanId)}/text`, { credentials: 'same-origin', signal: controller.signal });
        if (!response.ok) throw new Error(response.status === 401 ? 'Your session expired. Sign in again to view this scan.' : response.status === 404 ? 'This scan is no longer available.' : `Could not load this scan (${response.status}).`);
        if (!response.headers.get('content-type')?.includes('text/plain')) throw new Error('The server did not return scan text. Refresh and try again.');
        const output = await response.text();
        if (!controller.signal.aborted) setText(output);
      } catch (err) { if (!controller.signal.aborted) setError(err.message); }
    }
    void load();
    return () => controller.abort();
  }, [scanId, retry]);
  const lines = useMemo(() => text === null || text === '' ? [] : text.split('\n'), [text]);
  const matches = useMemo(() => query ? lines.flatMap((line, index) => line.toLowerCase().includes(query.toLowerCase()) ? [index] : []) : [], [lines, query]);
  const selectedMatch = matches.length ? matches[Math.min(matchIndex, matches.length - 1)] : -1;
  const pages = Math.max(1, Math.ceil(lines.length / SCAN_PAGE_SIZE));
  const page = selectedMatch >= 0 ? Math.floor(selectedMatch / SCAN_PAGE_SIZE) : Math.min(manualPage, pages - 1);
  const start = page * SCAN_PAGE_SIZE;
  useEffect(() => { currentLine.current?.scrollIntoView({ block: 'nearest' }); }, [selectedMatch, page]);
  function changePage(next) { setQuery(''); setMatchIndex(0); setManualPage(next); }
  async function copy() {
    try {
      if (navigator.clipboard && window.isSecureContext) await navigator.clipboard.writeText(text);
      else {
        const previous = document.activeElement;
        const input = document.createElement('textarea');
        input.value = text; input.style.position = 'fixed'; input.style.opacity = '0';
        dialog.current.append(input); input.select();
        try { if (!document.execCommand('copy')) throw new Error(); }
        finally { input.remove(); previous?.focus({ preventScroll: true }); }
      }
      setNotice('Full scan copied.');
    } catch { setNotice('Copy unavailable. Select the text or download the scan.'); }
  }
  function download() {
    const url = URL.createObjectURL(new Blob([text], { type: 'text/plain;charset=utf-8' }));
    const link = document.createElement('a'); link.href = url; link.download = `scan-${scanId.slice(0, 8)}.txt`;
    document.body.append(link); link.click(); link.remove(); setTimeout(() => URL.revokeObjectURL(url), 1000);
  }
  return createPortal(<dialog ref={dialog} className="scan-viewer" aria-labelledby="scan-viewer-title" onCancel={event => { event.preventDefault(); onClose(); }}>
    <header className="scan-viewer-header"><div><h2 id="scan-viewer-title">Scan output</h2><p className="hint">{title}</p></div><button autoFocus className="icon-button" onClick={onClose} aria-label="Close scan output"><X size={20} /></button></header>
    <div className="scan-viewer-toolbar">
      <div className="search"><Search size={16} /><input aria-label="Find in scan" placeholder="Find a host, port or script…" value={query} onChange={event => { setQuery(event.target.value); setMatchIndex(0); }} disabled={text === null} />{query && <button className="icon-button" onClick={() => { setQuery(''); setManualPage(page); }} aria-label="Clear scan search"><X size={14} /></button>}</div>
      {query && <div className="row"><span className="hint" role="status">{matches.length ? `${Math.min(matchIndex + 1, matches.length)} of ${matches.length} matching lines` : 'No matches'}</span><button className="icon-button" aria-label="Previous scan match" disabled={!matches.length} onClick={() => setMatchIndex(index => (index - 1 + matches.length) % matches.length)}><ChevronLeft size={16} /></button><button className="icon-button" aria-label="Next scan match" disabled={!matches.length} onClick={() => setMatchIndex(index => (index + 1) % matches.length)}><ChevronRight size={16} /></button></div>}
      <label className="check"><input type="checkbox" checked={wrap} onChange={event => setWrap(event.target.checked)} />Wrap lines</label>
      <button className="small" disabled={text === null} onClick={copy}><Copy size={15} />Copy</button><button className="small" disabled={text === null} onClick={download}><Download size={15} />TXT</button>
    </div>
    {error ? <div className="scan-viewer-message"><p className="error" role="alert">{error}</p><button onClick={() => setRetry(value => value + 1)}>Try again</button></div> : text === null ? <p className="scan-viewer-message" role="status">Loading scan output…</p> : !text ? <p className="scan-viewer-message">This scan has no text output.</p> : <div className={`scan-viewer-output ${wrap ? 'wrap-lines' : ''}`} tabIndex={0} aria-label="Scan evidence text">
      {lines.slice(start, start + SCAN_PAGE_SIZE).map((line, offset) => {
        const number = start + offset;
        return <div key={number} ref={number === selectedMatch ? currentLine : null} className={`scan-output-line ${scanLineKind(line)} ${number === selectedMatch ? 'current-match' : ''}`}><span className="scan-line-number" aria-hidden="true">{number + 1}</span><code>{highlightScanLine(line, query).map((part, index) => part.match ? <mark key={index}>{part.text}</mark> : part.text)}{'\n'}</code></div>;
      })}
    </div>}
    <footer className="scan-viewer-footer"><span className="hint">Readable evidence from the saved scan. Copy and download include all lines.</span>{text !== null && lines.length > 0 && <div className="row"><button className="icon-button" disabled={page === 0} aria-label="Previous scan page" onClick={() => changePage(page - 1)}><ChevronLeft size={16} /></button><span className="hint">Lines {start + 1}–{Math.min(start + SCAN_PAGE_SIZE, lines.length)} of {lines.length}</span><button className="icon-button" disabled={page === pages - 1} aria-label="Next scan page" onClick={() => changePage(page + 1)}><ChevronRight size={16} /></button></div>}<span role="status" className="hint">{notice}</span></footer>
  </dialog>, document.body);
}
