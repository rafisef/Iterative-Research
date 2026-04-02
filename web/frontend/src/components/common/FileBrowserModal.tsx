import { useCallback, useEffect, useRef, useState } from 'react';
import { pathApi, type PathEntry } from '../../api/client';

interface FileBrowserModalProps {
  open: boolean;
  onClose: () => void;
  onSelect: (path: string) => void;
  dirsOnly?: boolean;
  title?: string;
}

export function FileBrowserModal({
  open,
  onClose,
  onSelect,
  dirsOnly = false,
  title = 'Browse Files',
}: FileBrowserModalProps) {
  const [currentPath, setCurrentPath] = useState('');
  const [entries, setEntries] = useState<PathEntry[]>([]);
  const [loading, setLoading] = useState(false);
  const modalRef = useRef<HTMLDivElement>(null);

  const fetchEntries = useCallback(async (prefix: string) => {
    setLoading(true);
    try {
      const data = await pathApi.autocomplete(prefix || './', dirsOnly);
      setEntries(data);
    } catch {
      setEntries([]);
    } finally {
      setLoading(false);
    }
  }, [dirsOnly]);

  useEffect(() => {
    if (open) {
      fetchEntries(currentPath);
    }
  }, [open, currentPath, fetchEntries]);

  useEffect(() => {
    if (!open) {
      setCurrentPath('');
      setEntries([]);
    }
  }, [open]);

  useEffect(() => {
    const handleEsc = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    if (open) document.addEventListener('keydown', handleEsc);
    return () => document.removeEventListener('keydown', handleEsc);
  }, [open, onClose]);

  const handleEntryClick = (entry: PathEntry) => {
    if (entry.is_dir) {
      setCurrentPath(entry.path);
    } else {
      onSelect(entry.path);
      onClose();
    }
  };

  const handleSelectDir = () => {
    if (currentPath) {
      onSelect(currentPath);
      onClose();
    }
  };

  const goUp = () => {
    const parts = currentPath.replace(/\/$/, '').split('/');
    parts.pop();
    setCurrentPath(parts.length > 0 ? parts.join('/') + '/' : '');
  };

  if (!open) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
      <div ref={modalRef} className="w-full max-w-xl bg-slate-900 border border-slate-700 rounded-xl shadow-2xl flex flex-col max-h-[70vh]">
        <div className="flex items-center justify-between px-4 py-3 border-b border-slate-700">
          <h3 className="text-sm font-medium text-slate-200">{title}</h3>
          <button onClick={onClose} className="text-slate-500 hover:text-slate-300">
            <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>

        <div className="flex items-center gap-2 px-4 py-2 bg-slate-800/50 border-b border-slate-700/50">
          <button onClick={goUp} disabled={!currentPath} className="px-2 py-1 text-xs bg-slate-700 rounded hover:bg-slate-600 text-slate-300 disabled:opacity-30">
            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7" />
            </svg>
          </button>
          <span className="text-xs text-slate-400 font-mono truncate flex-1">{currentPath || './'}</span>
          {dirsOnly && currentPath && (
            <button
              onClick={handleSelectDir}
              className="px-3 py-1 text-xs bg-blue-600 hover:bg-blue-700 rounded text-white"
            >
              Select this directory
            </button>
          )}
        </div>

        <div className="flex-1 overflow-auto">
          {loading ? (
            <div className="flex justify-center py-8">
              <div className="w-5 h-5 border-2 border-blue-500 border-t-transparent rounded-full animate-spin" />
            </div>
          ) : entries.length === 0 ? (
            <p className="text-sm text-slate-500 text-center py-8">No entries found</p>
          ) : (
            <ul>
              {entries.map((entry) => (
                <li
                  key={entry.path}
                  onClick={() => handleEntryClick(entry)}
                  className="flex items-center gap-3 px-4 py-2 hover:bg-slate-800/50 cursor-pointer text-sm transition-colors border-b border-slate-800/30"
                >
                  {entry.is_dir ? (
                    <svg className="w-4 h-4 text-amber-400 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-6l-2-2H5a2 2 0 00-2 2z" />
                    </svg>
                  ) : (
                    <svg className="w-4 h-4 text-slate-500 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                    </svg>
                  )}
                  <span className="font-mono text-slate-300 truncate">{entry.path.split('/').pop() || entry.path}</span>
                  {entry.is_dir && (
                    <svg className="w-3 h-3 text-slate-600 ml-auto" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
                    </svg>
                  )}
                </li>
              ))}
            </ul>
          )}
        </div>
      </div>
    </div>
  );
}
