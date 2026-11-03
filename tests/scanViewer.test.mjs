import assert from 'node:assert/strict';
import { test } from 'node:test';
import { highlightScanLine, scanLineKind } from '../src/scanViewer.js';

test('recognizes hosts, port states and script headings', () => {
  assert.equal(scanLineKind('Host: 192.0.2.1'), 'host');
  assert.equal(scanLineKind('22/tcp  open  ssh'), 'open');
  assert.equal(scanLineKind('53/udp  open|filtered  domain'), 'port');
  assert.equal(scanLineKind('  ssh-hostkey:'), 'script');
  assert.equal(scanLineKind('ordinary evidence'), '');
});

test('search highlights literal text case insensitively without altering evidence', () => {
  const line = '<script>[SSH].* ssh [ssh].*</script>';
  const parts = highlightScanLine(line, '[ssh].*');
  assert.equal(parts.map(part => part.text).join(''), line);
  assert.deepEqual(parts.filter(part => part.match).map(part => part.text), ['[SSH].*', '[ssh].*']);
  assert.deepEqual(highlightScanLine(line, ''), [{ text: line, match: false }]);
  assert.deepEqual(highlightScanLine(line, 'missing'), [{ text: line, match: false }]);
});
