// Tokens always occupy a whole shell argument. Never interpolate raw values into shell syntax.
export const extraCommandFields = {
  TARGET_USER: { key: 'targetUser', label: 'Username to check', placeholder: 'alice (sAMAccountName)' },
  LISTENER: { key: 'listener', label: 'Your listener IP or hostname', placeholder: '192.0.2.50' },
  TEST_URL: { key: 'testUrl', label: 'Test URL', placeholder: 'https://app.example/private/config' },
  BASELINE_CONFIG: { key: 'baselineConfig', label: 'Baseline curl config', placeholder: '/tmp/baseline.curl' },
  TEST_CONFIG: { key: 'testConfig', label: 'Test curl config', placeholder: '/tmp/test.curl' },
  REQUEST_FILE: { key: 'requestFile', label: 'Raw HTTP request file', placeholder: '/tmp/request.txt' },
  PARAMETER: { key: 'parameter', label: 'Parameter to test', placeholder: 'id' },
  MAIL_FROM: { key: 'mailFrom', label: 'Controlled sender', placeholder: 'sender@example.test' },
  MAIL_TO: { key: 'mailTo', label: 'Controlled recipient', placeholder: 'recipient@example.test' },
  TFTP_URL: { key: 'tftpUrl', label: 'Known TFTP file URL', placeholder: 'tftp://192.0.2.10/config.txt' },
  BUCKET: { key: 'bucket', label: 'Scoped S3 bucket', placeholder: 'competition-bucket' },
  OTHER_FILE: { key: 'otherFile', label: 'Comparison file', placeholder: '/tmp/original.txt' }
};
export const commandFields = {
  ...Object.fromEntries(Object.entries(extraCommandFields).map(([token, field]) => [token, field.label])),
  HOST: 'Target host', URL: 'Application URL', LOG_URL: 'Log URL', USER: 'Username',
  DATABASE: 'Database', LDAP_URI: 'DC / LDAP host', BIND_ID: 'LDAP bind identity',
  BASE_DN: 'LDAP base DN', SMB_USER: 'Username and domain', SMB_DOMAIN: 'SMB domain', SHARE: 'SMB share',
  DNS_SERVER_ARG: 'DNS server', DC_SRV: 'AD DNS domain', SSH_USER_HOST: 'Username and target host',
  SERVICE: 'Service unit', FILE: 'File path', SUBNET: 'Subnet', DOMAIN: 'DNS zone', COMMUNITY: 'SNMP community', DC: 'DC / LDAP host'
};
export function shellQuote(value) { return "'" + String(value).replaceAll("'", "'\\''") + "'"; }
const hostLike = value => !!value && !value.startsWith('-') && /^[a-zA-Z0-9_.:%-]+$/.test(value);
function subnetValue(value = '') {
  const [address, prefix, extra] = value.split('/');
  if (extra !== undefined || !/^\d{1,3}$/.test(prefix || '')) return '';
  if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(address)) {
    return address.split('.').every(part => Number(part) <= 255) && Number(prefix) <= 32 ? value : '';
  }
  if (!/^[a-fA-F0-9:]+$/.test(address) || !address.includes(':') || Number(prefix) > 128) return '';
  try { new URL(`http://[${address}]/`); return value; } catch { return ''; }
}
export function commandValues(context) {
  const domain = (context.domain || '').trim().replace(/\.$/, '');
  const fqdn = domain.includes('.') && domain.split('.').every(label => /^[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?$/.test(label));
  const user = (context.user || '').trim();
  const host = hostLike(context.host) ? context.host : '';
  const dc = hostLike(context.dc) ? context.dc : '';
  const dns = hostLike(context.dns) ? context.dns : '';
  const subnet = subnetValue(context.subnet);
  const explicitIdentity = /[@\\=]/.test(user);
  const smbUser = user ? (explicitIdentity || !domain ? user : `${domain}\\${user}`) : '';
  const ldapHost = dc.includes(':') ? `[${dc}]` : dc;
  const url = value => { try { const parsed = new URL(value); return ['http:', 'https:'].includes(parsed.protocol) && !parsed.username && !parsed.password ? value : ''; } catch { return ''; } };
  return {
    ...Object.fromEntries(Object.entries(extraCommandFields).map(([token, field]) => [token, context[field.key] || ''])),
    TEST_URL: url(context.testUrl),
    TFTP_URL: (() => { try { const parsed = new URL(context.tftpUrl); return parsed.protocol === 'tftp:' && !parsed.username && !parsed.password ? context.tftpUrl : ''; } catch { return ''; } })(),
    DC: dc,
    HOST: host, URL: url(context.url), LOG_URL: url(context.logUrl), USER: user,
    DATABASE: context.database || '', LDAP_URI: dc ? `ldap://${ldapHost}` : '',
    BIND_ID: context.bind || (explicitIdentity ? user : user && fqdn ? `${user}@${domain}` : ''),
    BASE_DN: context.base || (fqdn ? domain.split('.').map(label => `DC=${label}`).join(',') : ''),
    SMB_USER: smbUser, SMB_DOMAIN: domain, SHARE: context.share || '',
    DNS_SERVER_ARG: dns ? `@${dns}` : '', DC_SRV: fqdn ? `_ldap._tcp.dc._msdcs.${domain}` : '',
    SSH_USER_HOST: user && host && !user.startsWith('-') ? `${user}@${host}` : '',
    SERVICE: context.service || '', FILE: context.file || '',
    SUBNET: subnet, DOMAIN: fqdn ? domain : '', COMMUNITY: context.community || ''
  };
}
export function renderCommand(template, context) {
  const values = commandValues(context);
  const missing = new Set();
  const text = template.replace(/\{([A-Z_]+)\}/g, (_, token) => {
    if (!values[token]) { missing.add(commandFields[token] || token); return `⟨${commandFields[token] || token}⟩`; }
    return shellQuote(values[token]);
  });
  return { text, missing: [...missing] };
}

const contextInputs = [
  { key: 'host', label: 'Target host', placeholder: 'IP address or hostname', tokens: ['HOST', 'SSH_USER_HOST'] },
  { key: 'dc', label: 'Domain controller', placeholder: 'dc01.example.local', tokens: ['DC', 'LDAP_URI'] },
  { key: 'domain', label: 'Domain', placeholder: 'example.local', tokens: ['DOMAIN', 'SMB_DOMAIN', 'SMB_USER', 'BASE_DN', 'BIND_ID', 'DC_SRV'] },
  { key: 'user', label: 'Username', placeholder: 'alice', tokens: ['USER', 'SMB_USER', 'BIND_ID', 'SSH_USER_HOST'] },
  { key: 'share', label: 'Share name', placeholder: 'SYSVOL', tokens: ['SHARE'] },
  { key: 'dns', label: 'DNS server', placeholder: '192.0.2.53', tokens: ['DNS_SERVER_ARG'] },
  { key: 'base', label: 'LDAP search base', placeholder: 'From domain; override with defaultNamingContext if needed', tokens: ['BASE_DN'] },
  { key: 'bind', label: 'LDAP login identity', placeholder: 'Defaults to username@domain', tokens: ['BIND_ID'] },
  { key: 'database', label: 'Database name', placeholder: 'postgres', tokens: ['DATABASE'] },
  { key: 'community', label: 'SNMP community', placeholder: 'Supplied community string', tokens: ['COMMUNITY'] },
  { key: 'service', label: 'Service unit', placeholder: 'app.service', tokens: ['SERVICE'] },
  { key: 'file', label: 'File path', placeholder: '/path/to/file', tokens: ['FILE'] },
  { key: 'url', label: 'Application URL', placeholder: 'https://app.example/', tokens: ['URL'] },
  { key: 'logUrl', label: 'Log URL', placeholder: 'https://app.example/query.log', tokens: ['LOG_URL'] },
  { key: 'subnet', label: 'Subnet', placeholder: '192.0.2.0/24', tokens: ['SUBNET'] }
];
export function contextFieldsFor(commands) {
  const tokens = new Set(commands.flatMap(command => [...(command || '').matchAll(/\{([A-Z_]+)\}/g)].map(match => match[1])));
  return contextInputs.filter(field => field.tokens.some(token => tokens.has(token)));
}
