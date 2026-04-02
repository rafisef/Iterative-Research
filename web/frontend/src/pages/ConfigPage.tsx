import { useCallback, useEffect, useState } from 'react';
import CodeMirror from '@uiw/react-codemirror';
import { yaml } from '@codemirror/lang-yaml';
import { EditorView } from '@codemirror/view';
import { configApi } from '../api/client';
import { Spinner } from '../components/common/Spinner';

const darkTheme = EditorView.theme({
  '&': { backgroundColor: '#0f172a', color: '#e2e8f0' },
  '.cm-gutters': { backgroundColor: '#1e293b', color: '#64748b', border: 'none' },
  '.cm-activeLine': { backgroundColor: '#1e293b50' },
  '.cm-activeLineGutter': { backgroundColor: '#1e293b' },
  '&.cm-focused .cm-cursor': { borderLeftColor: '#3b82f6' },
  '&.cm-focused .cm-selectionBackground, .cm-selectionBackground': { backgroundColor: '#3b82f630' },
});

export function ConfigPage() {
  const [content, setContent] = useState('');
  const [parsed, setParsed] = useState<Record<string, unknown> | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');
  const [saveMsg, setSaveMsg] = useState('');

  const fetchConfig = useCallback(async () => {
    try {
      const data = await configApi.get();
      setContent(data.raw);
      setParsed(data.parsed);
      if (data.error) setError(data.error);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load config');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { fetchConfig(); }, [fetchConfig]);

  const handleSave = async () => {
    setSaving(true);
    setError('');
    setSaveMsg('');
    try {
      const result = await configApi.put(content);
      setParsed(result.parsed);
      setSaveMsg('Saved successfully');
      setTimeout(() => setSaveMsg(''), 3000);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to save');
    } finally {
      setSaving(false);
    }
  };

  if (loading) return <div className="flex justify-center py-20"><Spinner size="lg" /></div>;

  return (
    <div className="flex gap-6 h-[calc(100vh-5rem)]">
      {/* Editor */}
      <div className="flex-1 flex flex-col">
        <div className="flex items-center justify-between mb-4">
          <div>
            <h2 className="text-2xl font-bold text-white">Configuration</h2>
            <p className="text-sm text-slate-400 mt-1">config/config.yaml</p>
          </div>
          <div className="flex items-center gap-3">
            {saveMsg && <span className="text-sm text-emerald-400">{saveMsg}</span>}
            {error && <span className="text-sm text-red-400">{error}</span>}
            <button
              onClick={handleSave}
              disabled={saving}
              className="flex items-center gap-2 px-4 py-2 text-sm bg-blue-600 hover:bg-blue-700 rounded-lg text-white font-medium transition-colors disabled:opacity-50"
            >
              {saving ? <Spinner size="sm" /> : null}
              Save
            </button>
          </div>
        </div>
        <div className="flex-1 rounded-xl overflow-hidden border border-slate-700/50">
          <CodeMirror
            value={content}
            onChange={(val) => setContent(val)}
            extensions={[yaml(), darkTheme]}
            height="100%"
            className="h-full"
            basicSetup={{
              lineNumbers: true,
              foldGutter: true,
              highlightActiveLineGutter: true,
              highlightActiveLine: true,
            }}
          />
        </div>
      </div>

      {/* Parsed tree preview */}
      <div className="w-80 flex flex-col">
        <h3 className="text-sm font-medium text-slate-400 mb-3">Parsed Structure</h3>
        <div className="flex-1 bg-slate-900/50 rounded-xl border border-slate-700/50 p-4 overflow-auto">
          {parsed ? (
            <TreeView data={parsed} />
          ) : (
            <p className="text-sm text-slate-500 italic">Invalid YAML — cannot display tree</p>
          )}
        </div>
      </div>
    </div>
  );
}

function TreeView({ data, depth = 0 }: { data: unknown; depth?: number }) {
  if (data === null || data === undefined) {
    return <span className="text-slate-500">null</span>;
  }
  if (typeof data !== 'object') {
    if (typeof data === 'string') return <span className="text-emerald-400">"{data}"</span>;
    if (typeof data === 'number') return <span className="text-amber-400">{data}</span>;
    if (typeof data === 'boolean') return <span className="text-blue-400">{data ? 'true' : 'false'}</span>;
    return <span className="text-slate-300">{String(data)}</span>;
  }
  if (Array.isArray(data)) {
    return (
      <div style={{ paddingLeft: depth > 0 ? 12 : 0 }}>
        {data.map((item, i) => (
          <div key={i} className="flex">
            <span className="text-slate-600 mr-1">-</span>
            <TreeView data={item} depth={depth + 1} />
          </div>
        ))}
      </div>
    );
  }
  const entries = Object.entries(data as Record<string, unknown>);
  return (
    <div style={{ paddingLeft: depth > 0 ? 12 : 0 }}>
      {entries.map(([key, val]) => (
        <div key={key} className="text-xs leading-5">
          <span className="text-blue-400">{key}</span>
          <span className="text-slate-600">: </span>
          {typeof val === 'object' && val !== null ? (
            <TreeView data={val} depth={depth + 1} />
          ) : (
            <TreeView data={val} depth={depth + 1} />
          )}
        </div>
      ))}
    </div>
  );
}
