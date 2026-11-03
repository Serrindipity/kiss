export async function api(path, { json, ...options } = {}) {
  const response = await fetch(`/api${path}`, {
    ...options,
    credentials: 'same-origin',
    headers: { 'X-Kiss-Request': '1', ...(json ? { 'Content-Type': 'application/json' } : {}), ...options.headers },
    body: json ? JSON.stringify(json) : options.body,
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    const detail = Array.isArray(data.detail)
      ? data.detail.map(item => `${item.loc?.slice(1).join('.')}: ${item.msg}`).join('; ')
      : data.detail;
    const error = new Error(detail || `Request failed (${response.status}).`);
    error.status = response.status;
    throw error;
  }
  return data;
}

export const hostName = host => host.hostname || host.address;
export const portName = port => `${port.port}/${port.protocol}`;
export const openPorts = host => host.ports.filter(port => port.state === 'open' || port.state === 'open|filtered');
export const displayTime = value => value ? new Date(typeof value === 'number' ? value * 1000 : value).toLocaleString() : 'Not scanned';
