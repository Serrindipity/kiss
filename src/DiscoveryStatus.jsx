import { ChevronDown } from 'lucide-react';

export default function DiscoveryStatus({ discovery }) {
  if (!discovery) return null;
  const { status, message = '' } = discovery;
  const responding = message.match(/(\d+) responding hosts found/);
  const summary = status === 'Complete'
    ? responding ? `${responding[1]} hosts responded` : 'Discovery complete'
    : status === 'Running' ? 'Discovering hosts…'
    : status === 'Failed' ? 'Discovery failed'
    : status === 'Interrupted' ? 'Discovery interrupted'
    : status === 'Not started' ? 'Discovery not started'
    : status;
  return <div className="discovery-result">
    <span className="hint" role="status">{summary}</span>
    {message && <details className="discovery-details"><summary>Details <ChevronDown size={13} /></summary><p className="hint">{message}</p></details>}
  </div>;
}
