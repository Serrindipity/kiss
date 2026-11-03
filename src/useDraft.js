import { useEffect, useRef, useState } from 'react';

// Drafts stay in this browser tab through navigation, refresh, and a session expiry.
export default function useDraft(key, initial) {
  const [value, setValue] = useState(() => {
    try { return JSON.parse(sessionStorage.getItem(key)) || initial; }
    catch { return initial; }
  });
  const baseline = useRef(initial);
  const dirty = JSON.stringify(value) !== JSON.stringify(baseline.current);
  useEffect(() => {
    try {
      if (dirty) sessionStorage.setItem(key, JSON.stringify(value));
      else sessionStorage.removeItem(key);
    } catch { /* Server saves still work when storage is unavailable. */ }
  }, [key, value, dirty]);
  useEffect(() => {
    if (!dirty && initial.revision > baseline.current.revision) {
      baseline.current = initial;
      setValue(initial);
    }
  }, [initial, dirty]);
  function accept(saved) {
    baseline.current = saved;
    setValue(saved);
    try { sessionStorage.removeItem(key); } catch { /* Storage may be disabled. */ }
  }
  return { value, setValue, dirty, accept };
}
