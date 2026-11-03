import { useEffect, useRef } from 'react';

// One active screen handles Escape; native dialogs handle their own cancellation.
export default function useEscape(onEscape, enabled = true) {
  const callback = useRef(onEscape);
  callback.current = onEscape;
  useEffect(() => {
    if (!enabled) return;
    function handle(event) {
      if (event.key !== 'Escape' || event.defaultPrevented || event.isComposing || document.querySelector('dialog[open]')) return;
      event.preventDefault();
      callback.current();
    }
    document.addEventListener('keydown', handle);
    return () => document.removeEventListener('keydown', handle);
  }, [enabled]);
}
