export function relativeTime(timestamp, now = Date.now()) {
  const seconds = Math.max(0, Math.floor((now - timestamp * 1000) / 1000));
  if (seconds < 60) return 'just now';
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes} minute${minutes === 1 ? '' : 's'} ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours} hour${hours === 1 ? '' : 's'} ago`;
  const days = Math.floor(hours / 24);
  return `${days} day${days === 1 ? '' : 's'} ago`;
}

export function groupActivity(events) {
  const result = [];
  const scans = new Map();
  // Events arrive newest first; walk chronologically so every queued scan starts a new group.
  for (const event of [...events].reverse()) {
    const scan = event.action.startsWith('port scan ') || event.action.startsWith('discovery ');
    if (!scan) { result.push({ ...event, history: [event] }); continue; }
    const key = `${event.kind}:${event.target_id}`;
    const status = event.action.replace(/^(port scan|discovery) /, '');
    let entry = scans.get(key);
    if (!entry || status === 'queued') {
      entry = { ...event, history: [] };
      result.push(entry);
      scans.set(key, entry);
    }
    const id = entry.id;
    Object.assign(entry, event, { id, scan: true, status });
    entry.history.push(event);
    if (['complete', 'failed', 'cancelled', 'interrupted', 'not started'].includes(status)) scans.delete(key);
  }
  return result.sort((a, b) => b.at - a.at);
}

export function actionText(event) {
  const actions = {
    'added scope': 'added to scope', 'imported a scan': 'imported scan results for',
    'renamed host': 'renamed', 'deleted host': 'deleted', 'changed owner': 'assigned', 'updated host': 'updated',
    'added finding': 'added a finding', 'updated finding': 'updated a finding',
    'added credential': 'added a credential', 'updated credential': 'updated a credential',
    'updated DNS settings': 'updated DNS for', 'authorized user': 'authorized', 'removed user': 'removed access for',
  };
  if (!event.scan) return actions[event.action] || event.action;
  const task = event.kind === 'host' ? 'port scan' : 'host discovery';
  return ({ queued: `queued a ${task} for`, running: `is running ${task} on`, complete: `finished ${task === 'port scan' ? 'scanning' : 'host discovery on'}`, failed: `could not finish ${task} on`, cancelled: `cancelled ${task} on`, interrupted: `had ${task} interrupted on`, 'not started': `could not start ${task} on` })[event.status] || event.action;
}

export function hostHue(id) {
  let hash = 0;
  for (const char of id || '') hash = (hash * 31 + char.charCodeAt(0)) >>> 0;
  return 155 + hash % 146;
}

export function activityDetail(event) {
  if (!event.scan) return event.detail;
  if (event.status === 'complete') {
    const ports = event.detail.match(/(\d+) open TCP ports/);
    if (ports) return `Found ${ports[1]} open TCP ports`;
    const hosts = event.detail.match(/(\d+) responding hosts/);
    if (hosts) return `Found ${hosts[1]} responding hosts`;
    return 'Results saved';
  }
  if (event.status === 'queued') return 'Waiting for a scan slot';
  if (event.status === 'running') return event.detail;
  if (event.status === 'cancelled') return 'Previous evidence was kept';
  return 'See scan history for details';
}
