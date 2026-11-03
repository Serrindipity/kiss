export const SCAN_PAGE_SIZE = 250;

export function scanLineKind(line) {
  if (/^(Host:|Nmap scan report for )/.test(line)) return 'host';
  const port = line.match(/^\d+\/(?:tcp|udp)\s+(\S+)/);
  if (port) return port[1] === 'open' ? 'open' : 'port';
  if (/^\s*[\w.-]+:\s*$/.test(line)) return 'script';
  return '';
}

// Keep all evidence as text. Never turn script output into HTML.
export function highlightScanLine(line, query) {
  if (!query) return [{ text: line, match: false }];
  const parts = [];
  const lower = line.toLowerCase(), needle = query.toLowerCase();
  let cursor = 0, index;
  while ((index = lower.indexOf(needle, cursor)) !== -1) {
    if (index > cursor) parts.push({ text: line.slice(cursor, index), match: false });
    parts.push({ text: line.slice(index, index + query.length), match: true });
    cursor = index + query.length;
  }
  if (cursor < line.length) parts.push({ text: line.slice(cursor), match: false });
  return parts;
}
