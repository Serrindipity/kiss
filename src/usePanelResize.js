import { useEffect, useRef, useState } from 'react';

const MIN = 320;
const DEFAULT = 460;
const KEY = 'kiss:host-panel-width';

export default function usePanelResize() {
  const container = useRef(null);
  const [width, setWidth] = useState(() => {
    try { const saved = Number(localStorage.getItem(KEY)); return saved >= MIN && Number.isFinite(saved) ? saved : DEFAULT; }
    catch { return DEFAULT; }
  });
  const [maximum, setMaximum] = useState(800);
  const [dragging, setDragging] = useState(false);
  useEffect(() => {
    const node = container.current;
    const observer = new ResizeObserver(() => {
      if (window.innerWidth < 1100) return;
      const max = Math.max(MIN, node.getBoundingClientRect().width - 368);
      setMaximum(max);
      setWidth(current => Math.max(MIN, Math.min(current, max)));
    });
    observer.observe(node);
    return () => observer.disconnect();
  }, []);
  useEffect(() => {
    try { localStorage.setItem(KEY, String(width)); } catch { /* Resizing works without persistence. */ }
  }, [width]);
  function resize(value) { setWidth(Math.round(Math.max(MIN, Math.min(value, maximum)))); }
  const separator = {
    role: 'separator', tabIndex: 0, 'aria-label': 'Resize host details', 'aria-orientation': 'vertical',
    'aria-valuemin': MIN, 'aria-valuemax': Math.round(maximum), 'aria-valuenow': width,
    'aria-valuetext': `Host details ${width} pixels wide`, 'aria-controls': 'host-detail',
    onPointerDown: event => {
      if (event.button !== 0) return;
      event.preventDefault(); event.currentTarget.focus(); event.currentTarget.setPointerCapture(event.pointerId); setDragging(true);
    },
    onPointerMove: event => {
      if (event.currentTarget.hasPointerCapture(event.pointerId)) resize(container.current.getBoundingClientRect().right - event.clientX - 4);
    },
    onPointerUp: event => {
      if (event.currentTarget.hasPointerCapture(event.pointerId)) event.currentTarget.releasePointerCapture(event.pointerId);
      setDragging(false);
    },
    onLostPointerCapture: () => setDragging(false),
    onPointerCancel: () => setDragging(false),
    onDoubleClick: () => resize(DEFAULT),
    onKeyDown: event => {
      const next = { ArrowLeft: width + 16, ArrowRight: width - 16, Home: MIN, End: maximum }[event.key];
      if (next !== undefined) { event.preventDefault(); resize(next); }
    },
  };
  return { container, width, dragging, separator };
}
