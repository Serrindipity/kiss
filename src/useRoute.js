import { useEffect, useState } from 'react';

export function readRoute() {
  const page = window.location.pathname.replace(/^\/+|\/+$/g, '') || 'home';
  const params = new URLSearchParams(window.location.search);
  return { page: ['home', 'scope', 'findings', 'credentials', 'users', 'cheatsheet', 'automation'].includes(page) ? page : 'home',
    ...Object.fromEntries(['network', 'host', 'finding', 'credential', 'edit', 'run'].filter(key => params.has(key)).map(key => [key, params.get(key)])) };
}

export function routeHref({ page, ...parameters }) {
  const query = new URLSearchParams(Object.entries(parameters).filter(([, value]) => value != null && value !== ''));
  return `/${page}${query.size ? `?${query}` : ''}`;
}

export function shouldNavigate(event) {
  return !event.defaultPrevented && event.button === 0 && !event.metaKey && !event.ctrlKey && !event.shiftKey && !event.altKey;
}

export default function useRoute() {
  const [route, setRoute] = useState(readRoute);
  useEffect(() => {
    const pop = () => setRoute(readRoute());
    window.addEventListener('popstate', pop);
    return () => window.removeEventListener('popstate', pop);
  }, []);
  function navigate(next) {
    const url = routeHref(next);
    if (url !== window.location.pathname + window.location.search) window.history.pushState(null, '', url);
    setRoute(readRoute());
  }
  return [route, navigate];
}
