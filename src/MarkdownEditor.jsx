import { useId, useRef, useState } from 'react';
import Markdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import { ImagePlus } from 'lucide-react';
import { api } from './api';

export function MarkdownView({ children }) {
  return <div className="markdown"><Markdown remarkPlugins={[remarkGfm]} skipHtml>{children || '*Nothing written yet.*'}</Markdown></div>;
}

export default function MarkdownEditor({ label, value, onChange, onBusyChange, placeholder, rows = 7 }) {
  const id = useId();
  const textarea = useRef(null);
  const fileInput = useRef(null);
  const [preview, setPreview] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [error, setError] = useState('');
  async function insertImages(files) {
    if (!files.length || uploading) return;
    const start = textarea.current?.selectionStart ?? value.length;
    const end = textarea.current?.selectionEnd ?? start;
    const original = value;
    setUploading(true);
    onBusyChange?.(true);
    setError('');
    const inserted = [];
    try {
      for (const file of files) {
        if (file.size > 10 * 1024 * 1024) throw new Error('Each image must be smaller than 10 MB.');
        const result = await api('/attachments', { method: 'POST', body: file });
        const url = new URL(result.path, window.location.origin).href;
        inserted.push(`![image](${url})`);
      }
    } catch (err) {
      setError(err.message);
    } finally {
      if (inserted.length) {
        const text = inserted.join('\n');
        onChange(original.slice(0, start) + text + original.slice(end));
        requestAnimationFrame(() => {
          textarea.current?.focus();
          textarea.current?.setSelectionRange(start + text.length, start + text.length);
        });
      }
      setUploading(false);
      onBusyChange?.(false);
    }
  }
  function paste(event) {
    const files = [...event.clipboardData.items].filter(item => item.kind === 'file' && item.type.startsWith('image/')).map(item => item.getAsFile()).filter(Boolean);
    if (files.length) {
      event.preventDefault();
      void insertImages(files);
    }
  }
  return <section className="md-editor">
    <div className="editor-heading">
      <label htmlFor={id}>{label}</label>
      <div className="segmented" aria-label={`${label} mode`}>
        <button type="button" aria-pressed={!preview} onClick={() => setPreview(false)}>Write</button>
        <button type="button" aria-pressed={preview} onClick={() => setPreview(true)}>Preview</button>
      </div>
    </div>
    {preview ? <div className="preview-pane"><MarkdownView>{value}</MarkdownView></div> :
      <textarea id={id} ref={textarea} value={value} readOnly={uploading} onChange={event => onChange(event.target.value)} onPaste={paste} rows={rows} placeholder={placeholder || 'Write in Markdown…'} />}
    <div className="editor-footer">
      <span role="status">{uploading ? 'Uploading image…' : 'Markdown · Paste images to upload'}</span>
      <button type="button" className="quiet small" disabled={uploading || preview} onClick={() => fileInput.current?.click()} aria-label={`Attach image to ${label}`}><ImagePlus size={16} /> Image</button>
      <input ref={fileInput} type="file" accept="image/png,image/jpeg,image/webp,image/gif" multiple hidden onChange={event => { void insertImages([...event.target.files]); event.target.value = ''; }} />
    </div>
    {error && <p className="error" role="alert">{error} Your text has been kept.</p>}
  </section>;
}
