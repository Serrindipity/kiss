import assert from 'node:assert/strict';
import { checkTitle, checkState, checkSummary, cleanOutput, formatCommand } from '../src/automationResults.js';

assert.equal(checkTitle({ id: 'ldap-rootdse' }), 'Read directory server metadata · LDAP RootDSE');
assert.equal(checkTitle({ path: 'Policy/my_file.xml' }), 'Policy/my_file.xml');
assert.equal(checkState({ status: 'completed' }).label, 'Finished');
assert.equal(checkState({ status: 'not_tested', reason: 'plan_only' }).label, 'Preview');
assert.equal(checkState({ status: 'partial' }).tone, 'attention');
assert.equal(checkSummary({ status: 'completed', data: [] }), '0 records returned');
assert.equal(checkSummary({ status: 'partial', data: [{}] }), '1 record returned (incomplete)');
assert.equal(checkSummary({ status: 'error', data: [] }), 'The command failed; inspect the error output');
assert.equal(checkSummary({ data: { hosts: [{ ports: [{ state: 'open' }, { state: 'closed' }], scripts: [{}] }] } }), '1 open port · 1 script result');
assert.equal(cleanOutput('\x1b[31mfailed\x1b[0m\r\n<script>'), 'failed\n<script>');
assert.equal(formatCommand(['ldapsearch', '-b', 'DC=a,DC=b', '(objectClass=*)', "a'b"]), "ldapsearch -b DC=a,DC=b '(objectClass=*)' 'a'\\''b'");
console.log('PASS: automation summaries, states, plain output and command quoting');


const { isToolSetup } = await import('../src/automationResults.js');
assert.equal(isToolSetup({ id: 'netexec-ftp-help' }), true);
assert.equal(isToolSetup({ id: 'ftp-anonymous' }), false);
assert.equal(isToolSetup({ id: 'netexec-winrm-modules' }), true);

const { readFileSync } = await import('node:fs');
const { checkTitles } = await import('../src/automationResults.js');
for (const [file, pattern] of [
  ['scripts/dc_checks/lab_catalog.py', /Check\("([^"]+)"/g],
  ['scripts/dc_checks/ldap_checks.py', /\("([\w-]+)", "(?:domain|config)"/g],
  ['scripts/dc_checks/Collect-DomainChecks.ps1', /Invoke-Check '([^']+)'/g],
]) {
  for (const [, id] of readFileSync(file, 'utf8').matchAll(pattern)) {
    assert.ok(checkTitles[id], `Missing explicit title for ${id} in ${file}`);
  }
}
assert.match(checkTitle({ id: 'spooler' }), /Print Spooler/);
assert.match(checkTitle({ id: 'ms17-010' }), /EternalBlue/);
assert.match(checkTitle({ id: 'petitpotam', evidence_kind: 'rpc_interface_exposure' }), /^Check RPC interface exposure/);
assert.match(checkTitle({ id: 'petitpotam', evidence_kind: 'coercion_attempt' }), /^Attempt an authentication callback/);
assert.match(checkTitle({ id: 'ldap389-domain-policy' }), /LDAP 389$/);
assert.match(checkTitle({ id: 'netexec-ftp-help' }), /FTP command options/);
assert.match(checkTitle({ id: 'local-hotfixes' }), /collector machine/);
console.log(`PASS: ${Object.keys(checkTitles).length} named checks; complete catalog and imported collector title coverage`);
