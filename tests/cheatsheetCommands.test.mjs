import assert from 'node:assert/strict';
import {sections, filterSections} from '../src/cheatsheet.js';
import {shellQuote,commandValues,renderCommand,contextFieldsFor} from '../src/cheatsheetCommands.js';
const entries=sections.flatMap(s=>s.groups.flatMap(g=>g.items));
const c={targetUser:"alice",listener:"192.0.2.50",testUrl:'https://app.example/private',baselineConfig:'/tmp/baseline.curl',testConfig:'/tmp/test.curl',requestFile:'/tmp/request.txt',parameter:'id',mailFrom:'sender@example.test',mailTo:'recipient@example.test',tftpUrl:'tftp://192.0.2.10/config.txt',bucket:'competition-bucket',otherFile:'/tmp/original.txt',subnet:'192.0.2.0/24',community:'public',domain:'corp.example',host:'192.0.2.10',dc:'dc.corp.example',dns:'192.0.2.53',user:'alice',url:'https://app.corp.example/',logUrl:'https://app.corp.example/query.log',database:'app',share:'SYSVOL',service:'app.service',file:'/opt/app/main.js'};
assert.equal(commandValues(c).BASE_DN,'DC=corp,DC=example');
assert.equal(commandValues(c).BIND_ID,'alice@corp.example');
assert.equal(commandValues(c).SMB_USER,'corp.example\\alice');
assert.equal(commandValues({...c,domain:'CORP'}).BASE_DN,'');
assert.equal(commandValues({...c,domain:'CORP'}).BIND_ID,'');
assert.equal(commandValues({...c,dc:'',dns:'192.0.2.53'}).LDAP_URI,'');
assert.equal(commandValues({...c,dc:'2001:db8::1'}).LDAP_URI,'ldap://[2001:db8::1]');
assert.equal(commandValues({...c,domain:'corp.example',base:'OU=People,DC=other,DC=test'}).BASE_DN,'OU=People,DC=other,DC=test');
assert.equal(commandValues({...c,host:'-oN /tmp/out'}).HOST,'');
assert.equal(commandValues({...c,url:'javascript:alert(1)'}).URL,'');
assert.equal(commandValues({...c,url:'https://user:secret@example.com'}).URL,'');
assert.equal(shellQuote("a'b;$(id)"),"'a'\\''b;$(id)'");
assert.deepEqual(renderCommand('ldapsearch -b {BASE_DN}',{}).missing,['LDAP base DN']);
for(const e of entries){
 assert(e.title&&e.check&&e.evidence&&e.caveat);
 assert(e.guidance?.trim(), `${e.title}: missing concise explanation`);
 if(e.mode === 'workflow') assert.equal(e.command, '');
 else assert(e.command?.trim(), `${e.title}: missing test command`);
 assert(e.validation?.trim(), `${e.title}: missing finding criterion`);
 if(e.command) assert(e.runOn?.trim(), `${e.title}: missing execution context`);
 if(e.command){const r=renderCommand(e.command,c);assert.deepEqual(r.missing,[],e.title);assert(!/\{[A-Z_]+\}/.test(r.text),e.title);}
 for(const s of e.sources||[])assert(s.report&&s.pages&&s.status&&s.example);
}
const refs=new Set(entries.flatMap(e=>(e.sources||[]).map(s=>s.report)));
console.log(`PASS: ${entries.length} entries, ${entries.filter(e=>e.command).length} command examples, ${refs.size} cited reports; context derivation, missing values, URL validation, quoting, and all templates.`);

assert.equal(commandValues({...c, subnet:'-iL targets.txt'}).SUBNET, '');
assert.equal(commandValues({...c, subnet:'192.0.2.0/99'}).SUBNET, '');
assert.equal(commandValues({...c, subnet:'2001:db8::/64'}).SUBNET, '2001:db8::/64');
assert.equal(commandValues({...c, domain:'corp.example;id'}).DOMAIN, '');
assert.deepEqual(renderCommand('snmpwalk -c {COMMUNITY} {HOST}', {}).missing, ['SNMP community','Target host']);
assert(renderCommand('snmpwalk -c {COMMUNITY}', {...c, community: "x';$(id)"}).text.includes(shellQuote("x';$(id)")));
const seen = new Set();
for (const section of sections) {
 assert(!seen.has(section.id)); seen.add(section.id);
 const topics = new Set();
 for (const group of section.groups) {
  assert(!topics.has(group.title)); topics.add(group.title);
  assert(group.items.length > 0);
  const filtered = filterSections('', section.id, group.title);
  assert.equal(filtered.length, 1);
  assert.equal(filtered[0].groups.length, section.groups.length);
  assert.deepEqual(filtered[0].groups.find(item=>item.title===group.title).items, group.items);
  for (const item of group.items) for (const source of item.references || []) {
   assert(source.label); assert.equal(new URL(source.url).protocol, 'https:');
  }
 }
}
assert(filterSections(' MongoDB ', 'web', 'Accounts & authorization').some(s=>s.id==='linux'));
assert(filterSections('LDAP', 'web', 'Application & exposure').some(s=>s.id==='windows'));
assert.deepEqual(filterSections('definitely-no-matches-12345', 'web', 'Application & exposure'), []);
for (const subnet of ['999.0.0.1/24', '1/24', '::::/64', '2001:db8::/129', '192.0.2.0/24/1']) {
 assert.equal(commandValues({...c, subnet}).SUBNET, '', subnet);
}

assert.equal(commandValues({...c,testUrl:'file:///etc/passwd'}).TEST_URL,'');
assert.equal(commandValues({...c,tftpUrl:'http://example.test/file'}).TFTP_URL,'');
assert.deepEqual(renderCommand('curl --config {TEST_CONFIG}',{}).missing,['Test curl config']);
assert(filterSections('IDOR and role enforcement', 'web', 'Application & exposure').some(section => section.groups.some(group => group.items.some(item => item.title === 'Can one user access another user’s records? (IDOR)'))));

const webEntries = sections.find(section=>section.id==='web').groups.flatMap(group=>group.items);
assert(webEntries.every(item=>item.mode==='workflow' && !item.command));
assert.deepEqual(contextFieldsFor(webEntries.map(item=>item.command)), []);
assert.deepEqual(contextFieldsFor(['nxc smb {HOST} --share {SHARE}']).map(field=>field.key), ['host','share']);
assert.deepEqual(contextFieldsFor(['ldapsearch -H {LDAP_URI} -D {BIND_ID} -b {BASE_DN}']).map(field=>field.key), ['dc','domain','user','base','bind']);
assert.deepEqual(contextFieldsFor(['whoami /all']), []);

assert.deepEqual(sections.map(section=>section.id), ['web','windows','linux','cloud','findings']);
for (const id of ['windows','linux']) assert(sections.find(section=>section.id===id).groups.some(group=>group.items.some(item=>item.title==='FTP anonymous listing')));
