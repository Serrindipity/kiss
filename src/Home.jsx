import { useState } from 'react';
import { CheckCircle2, Clock3, CircleAlert, Activity } from 'lucide-react';
import { activityDetail, actionText, groupActivity, hostHue, relativeTime } from './activity';
import { displayTime, hostName } from './api';

export default function Home({ state, onOpen }) {
  const [filter, setFilter] = useState('all');
  const assigned = state.hosts.filter(host => host.owner === state.username);
  const events = groupActivity(state.activity || []).map(event => {
    if (!event.scan || !['queued', 'running'].includes(event.status)) return event;
    const job = event.kind === 'host' ? state.hosts.find(h => h.id === event.target_id)?.port_scan : state.networks.find(n => n.id === event.target_id)?.discovery;
    return job?.status === 'Running' ? { ...event, status: 'running', detail: job.phase || 'Scan in progress' } : event;
  }).filter(event => filter === 'all' || event.history.some(item => item.actor === state.username));
  return <main className="home-page">
    <header className="page-header"><h1>Home</h1></header>
    <div className="home-columns">
    <section className="home-hosts" aria-labelledby="your-hosts-title">
      <div className="row between"><h2 id="your-hosts-title">Your hosts <span className="home-count">{assigned.length}</span></h2><button className="quiet small" onClick={() => onOpen({ kind: 'scope' })}>View all</button></div>
      {assigned.length ? <ul className="assigned-hosts">{assigned.map(host => <li key={host.id}>
        <button className="assigned-host-link" onClick={() => onOpen({ kind: 'host', target_id: host.id })}>
          <span className="assigned-host-identity"><strong>{hostName(host)}</strong>{host.hostname && <code className="hint">{host.address}</code>}</span>
          <span className="assigned-host-status hint">{host.status}</span>
        </button>
      </li>)}</ul> : <p className="muted home-empty">No hosts assigned to you yet. Choose a host in Scope and use “Assign to me.”</p>}
    </section>
    <section className="home-activity" aria-labelledby="activity-title">
      <div className="row between"><h2 id="activity-title">Activity</h2><select aria-label="Filter activity" value={filter} onChange={event => setFilter(event.target.value)}><option value="all">Everyone</option><option value="mine">Only me</option></select></div>
      {events.length ? <ol className="activity-list">{events.map(event => {
        const assignedOwner = event.action === 'changed owner' && event.detail?.startsWith('Owner: ') ? event.detail.slice(7) : null;
        const credential = event.kind === 'credential' ? state.credentials.find(item => item.id === event.target_id) : null;
        const Icon = ['failed', 'interrupted', 'not started'].includes(event.status) ? CircleAlert : event.status === 'complete' ? CheckCircle2 : ['queued', 'running'].includes(event.status) ? Clock3 : Activity;
        return <li key={event.id} className={`activity-event ${['failed', 'interrupted', 'not started'].includes(event.status) ? 'activity-failed' : ''}`}>
          <Icon className="activity-icon" size={16} aria-hidden="true" />
          <div className="activity-body"><p><strong>{event.actor}</strong> {assignedOwner === 'Unassigned' ? 'unassigned' : actionText(event)}{event.label && <> {event.kind === 'user' ? <strong>{event.label}</strong> : <button className={`table-link ${event.kind === 'host' ? 'activity-host-label' : ''}`} style={event.kind === 'host' ? { '--host-hue': hostHue(event.target_id) } : undefined} onClick={() => onOpen(event)}>{event.label}</button>}</>}{assignedOwner && assignedOwner !== 'Unassigned' && <> to <strong>{assignedOwner}</strong></>}</p>
            {!assignedOwner && activityDetail(event) && <p className="hint">{activityDetail(event)}</p>}
            {event.scan && <details className="activity-history"><summary>Scan history</summary><ul>{event.history.map(item => <li key={item.id}><time>{displayTime(item.at)}</time> · {item.actor}: {item.action}<p>{item.detail}</p></li>)}</ul></details>}
            {credential && <details className="activity-secret"><summary>Current credential</summary><div className="hint">{credential.secret_type} · {credential.username || credential.service}</div><pre>{credential.secret || '(empty password)'}</pre></details>}
          </div><time className="hint activity-time" tabIndex={0} title={displayTime(event.at)} aria-label={`${relativeTime(event.at)}, ${displayTime(event.at)}`} dateTime={new Date(event.at * 1000).toISOString()}>{relativeTime(event.at)}<span className="activity-exact-time">{displayTime(event.at)}</span></time>
        </li>;
      })}</ol> : <p className="muted home-empty">{filter === 'mine' ? 'Your changes will appear here.' : 'No activity yet. New team changes will appear here.'}</p>}
      {!!events.length && <p className="hint">Latest 200 workspace events · updates automatically</p>}
    </section>
    </div>
  </main>;
}
