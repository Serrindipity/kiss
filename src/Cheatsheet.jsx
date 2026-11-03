import { useState } from 'react';
import { ChevronDown, Copy, Search, X } from 'lucide-react';
import { sections, filterSections } from './cheatsheet';
import { renderCommand, extraCommandFields, contextFieldsFor } from './cheatsheetCommands';
import './cheatsheet.css';

const topicId = (section, title) => `cheatsheet-topic-${section}-${title.toLowerCase().replace(/[^a-z0-9]+/g, '-')}`;

const categoryLabels = { web: 'Web', windows: 'Windows / AD', linux: 'Linux', findings: 'Reporting' };

function Command({ template, context }) {
  const [values, setValues] = useState({});
  const inputs = Object.entries(extraCommandFields).filter(([token]) => template.includes(`{${token}}`));
  const { text: value, missing } = renderCommand(template, { ...context, ...values });
  const [message, setMessage] = useState('');
  async function copy() {
    try {
      if (navigator.clipboard && window.isSecureContext) await navigator.clipboard.writeText(value);
      else {
        const previous = document.activeElement;
        const input = document.createElement('textarea');
        input.value = value; input.style.position = 'fixed'; input.style.left = '-9999px';
        document.body.append(input); input.select();
        try { if (!document.execCommand('copy')) throw new Error('Copy unavailable'); }
        finally { input.remove(); previous?.focus(); }
      }
      setMessage('Copied');
    } catch { setMessage('Select the command to copy'); }
  }
  return <>{template.includes('{BASELINE_CONFIG}') && <details className="cheatsheet-references"><summary>How to prepare the two request files <ChevronDown size={14} /></summary><p>A baseline is a request that works normally. Save it as a curl config file on the computer running the command, copy it, then make only the change described below. These are not raw Burp requests or shell scripts.</p><pre><code>{'url = "https://app.example/api/records/123"\nrequest = "GET"\nheader = "Cookie: session=YOUR_TEST_SESSION"'}</code></pre><p>Replace the example with your real URL and session. For POST requests, include the real Content-Type header and a data line containing the request body. Preserve any anti-forgery (CSRF) token. Enter both file paths below. The command saves responses in a new temporary folder and shows their differences.</p></details>}{inputs.length > 0 && <div className="cheatsheet-context-fields">{inputs.map(([token, field]) => <label className="field" key={token}>{field.label}<input value={values[field.key] || ''} onChange={event => { setValues(previous => ({ ...previous, [field.key]: event.target.value })); setMessage(''); }} placeholder={field.placeholder} autoComplete="off" spellCheck={false} /></label>)}</div>}<div className="cheatsheet-command"><pre><code>{value}</code></pre><button className="icon-button" aria-label="Copy command" title={missing.length ? `Fill in: ${missing.join(', ')}` : 'Copy command'} disabled={missing.length > 0} onClick={copy}><Copy size={15} /></button><span className="hint" role="status">{missing.length ? `Fill in: ${missing.join(', ')}` : message}</span></div></>;
}

export default function Cheatsheet({ state }) {
  const networks = state?.networks || [];
  const hosts = state?.hosts || [];
  const credentials = (state?.credentials || []).filter(c => c.username);
  const [networkId, setNetworkId] = useState(() => networks.length === 1 ? networks[0].id : '');
  const [hostId, setHostId] = useState('');
  const [overrides, setOverrides] = useState({});
  const selectedNetwork = networks.find(n => n.id === networkId);
  const selectedHost = hosts.find(h => h.id === hostId);
  const context = { subnet: selectedNetwork?.cidr || '', domain: selectedNetwork?.dns_zone || '', dns: selectedNetwork?.dns_server || '', host: selectedHost?.address || selectedHost?.hostname || '', ...overrides };
  const updateContext = (name, value) => setOverrides(previous => ({ ...previous, ...(name === 'domain' ? { base: '', bind: '' } : {}), [name]: value }));
  const field = (name, label, placeholder = '') => <label className="field" key={name}>{label}<input value={context[name] || ''} onChange={event => updateContext(name, event.target.value)} placeholder={placeholder} autoComplete="off" spellCheck={false} /></label>;
  const [active, setActive] = useState('web');
  const [query, setQuery] = useState('');
  const term = query.trim().toLowerCase();
  const category = sections.find(section => section.id === active);
  const visible = filterSections(query, active);
  const contextFields = contextFieldsFor(visible.flatMap(section => section.groups.flatMap(group => group.items.map(item => item.command))));
  const hasContext = name => contextFields.some(field => field.key === name);
  const count = visible.reduce((total, section) => total + section.groups.reduce((n, group) => n + group.items.length, 0), 0);
  return <main className="cheatsheet-main">
    <header className="page-header"><h1>Cheatsheet</h1><div className="search"><Search size={17} aria-hidden="true" /><input aria-label="Search all cheatsheet sections" value={query} onChange={event => setQuery(event.target.value)} placeholder="Search checks and commands…" />{query && <button className="icon-button" aria-label="Clear search" onClick={() => setQuery('')}><X size={16} /></button>}</div></header>
    <div className="cheatsheet-controls">
      <div className="cheatsheet-categories" role="group" aria-label="Cheatsheet sections">
        {sections.map(section => <button key={section.id} aria-pressed={!term && active === section.id} onClick={() => { setActive(section.id); setQuery(''); }}>{categoryLabels[section.id] || section.title}</button>)}
      </div>
      <span className="hint" role="status">{count} {count === 1 ? 'check' : 'checks'}{term ? ' across all sections' : ''}</span>
    </div>
    {!term && <nav className="cheatsheet-topics" aria-label={`${category.title} topics`}>
      {category.groups.map(group => <a key={group.title} href={`#${topicId(category.id, group.title)}`} onClick={event => { event.preventDefault(); const target = document.getElementById(topicId(category.id, group.title)); target?.focus({ preventScroll: true }); target?.scrollIntoView({ block: 'start' }); }}>{group.title}<span className="hint">{group.items.length}</span></a>)}
    </nav>}
    {contextFields.length > 0 && <details className="cheatsheet-context">
      <summary>Command values <ChevronDown size={14} /></summary>
      <p className="hint">Only values used in this section are shown. Fill them once to update the commands below.</p>
      <div className="cheatsheet-context-fields">
        {contextFields.filter(input => !['base', 'bind'].includes(input.key)).map(input => field(input.key, input.label, input.placeholder))}
      </div>
      {(hasContext('base') || hasContext('bind')) && <details><summary>LDAP overrides <ChevronDown size={14} /></summary><p className="hint">The search base and login name are filled from your domain and username. Override them only if the directory uses different values.</p><div className="cheatsheet-context-fields">
        {contextFields.filter(input => ['base', 'bind'].includes(input.key)).map(input => field(input.key, input.label, input.placeholder))}
      </div></details>}
      {((hasContext('host') && hosts.length > 0) || ((hasContext('domain') || hasContext('dns')) && networks.length > 0) || (hasContext('user') && credentials.length > 0)) && <details>
        <summary>Fill from workspace <ChevronDown size={14} /></summary>
        <div className="cheatsheet-context-fields">
          {(hasContext('domain') || hasContext('dns')) && networks.length > 0 && <label className="field">Network<select value={networkId} onChange={event => { setNetworkId(event.target.value); setOverrides(previous => { const { subnet, domain, dns, dc, base, bind, ...rest } = previous; return rest; }); }}><option value="">Choose a network</option>{networks.map(n => <option key={n.id} value={n.id}>{n.name || n.cidr}</option>)}</select></label>}
          {hasContext('host') && hosts.length > 0 && <label className="field">Host<select value={hostId} onChange={event => { setHostId(event.target.value); setOverrides(previous => { const { host, ...rest } = previous; return rest; }); }}><option value="">Choose a host</option>{hosts.map(h => <option key={h.id} value={h.id}>{h.hostname ? `${h.hostname} (${h.address})` : h.address}</option>)}</select></label>}
          {hasContext('user') && credentials.length > 0 && <label className="field">Saved account<select value="" onChange={event => { const c = credentials.find(item => item.id === event.target.value); if (c) setOverrides(previous => ({ ...previous, user: c.username, ...(c.domain ? {domain: c.domain, base: '', bind: ''} : {}) })); }}><option value="">Choose an account (username only)</option>{credentials.map(c => <option key={c.id} value={c.id}>{c.domain ? `${c.domain}\\` : ''}{c.username}</option>)}</select></label>}
        </div>
      </details>}
    </details>}
    {!count && <div className="empty-state"><h2>No matching checks</h2><p>Try a service, tool, or topic such as LDAP, sudo, or password.</p></div>}
    {visible.map(section => <section key={section.id} aria-labelledby={`cheatsheet-${section.id}`} className="cheatsheet-section">
      <h2 id={`cheatsheet-${section.id}`} className={term ? '' : 'sr-only'}>{section.title}</h2>{!term && <p className="cheatsheet-section-intro">{section.intro}</p>}
      {section.groups.map(group => <section key={group.title} className="cheatsheet-group"><h3 id={topicId(section.id, group.title)} tabIndex={-1}>{group.title.replace(/^\d+\.\s*/, '')}</h3>
        {group.items.map(item => <details key={`${section.id}-${item.title}-${!!term}`} className="cheatsheet-entry">
          <summary><span>{item.title}</span><ChevronDown size={15} aria-hidden="true" /></summary>
          <div className="cheatsheet-entry-body">
            {item.command && <><p className="hint">{item.runOn}</p><Command key={item.command} template={item.command} context={context} /></>}
            <p className="cheatsheet-guidance">{item.guidance}</p>
          {(item.references?.length > 0) && <details className="cheatsheet-references"><summary>References <ChevronDown size={14} /></summary>
            {item.references?.map(source => <p key={source.url}><a href={source.url} target="_blank" rel="noreferrer">{source.label}</a></p>)}
          </details>}</div>
        </details>)}
      </section>)}
    </section>)}
    <footer className="cheatsheet-sources"><details><summary>About this reference <ChevronDown size={14} /></summary><p>Use this reference to plan checks and interpret evidence. It is not a record of completed checks. Consult the linked tool and security documentation for details.</p>
      <a href="https://owasp.org/www-project-web-security-testing-guide/" target="_blank" rel="noreferrer">OWASP Web Security Testing Guide</a>{' · '}
      <a href="https://www.microsoft.com/en-us/msrc/blog/2020/10/attacks-exploiting-netlogon-vulnerability-cve-2020-1472" target="_blank" rel="noreferrer">Microsoft: Zerologon</a>{' · '}
      <a href="https://gtfobins.github.io/" target="_blank" rel="noreferrer">GTFOBins</a>
    </details></footer>
  </main>;
}
