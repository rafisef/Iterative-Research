import { useCallback, useEffect, useRef, useState } from 'react';
import { pathApi, type PathEntry } from '../../api/client';

interface PathAutocompleteProps {
  value: string;
  onChange: (val: string) => void;
  placeholder?: string;
  dirsOnly?: boolean;
}

export function PathAutocomplete({ value, onChange, placeholder, dirsOnly = false }: PathAutocompleteProps) {
  const [suggestions, setSuggestions] = useState<PathEntry[]>([]);
  const [open, setOpen] = useState(false);
  const [highlighted, setHighlighted] = useState(-1);
  const inputRef = useRef<HTMLInputElement>(null);
  const listRef = useRef<HTMLUListElement>(null);
  const debounceRef = useRef<ReturnType<typeof setTimeout>>(undefined);

  const fetchSuggestions = useCallback(
    (prefix: string) => {
      clearTimeout(debounceRef.current);
      debounceRef.current = setTimeout(async () => {
        if (!prefix) {
          setSuggestions([]);
          return;
        }
        try {
          const data = await pathApi.autocomplete(prefix, dirsOnly);
          setSuggestions(data);
          setOpen(data.length > 0);
          setHighlighted(-1);
        } catch {
          setSuggestions([]);
        }
      }, 150);
    },
    [dirsOnly],
  );

  useEffect(() => {
    return () => clearTimeout(debounceRef.current);
  }, []);

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const val = e.target.value;
    onChange(val);
    fetchSuggestions(val);
  };

  const handleSelect = (entry: PathEntry) => {
    onChange(entry.path);
    if (entry.is_dir) {
      fetchSuggestions(entry.path);
    } else {
      setOpen(false);
      setSuggestions([]);
    }
    inputRef.current?.focus();
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (!open || suggestions.length === 0) {
      if (e.key === 'Tab') {
        fetchSuggestions(value);
        e.preventDefault();
      }
      return;
    }

    switch (e.key) {
      case 'Tab':
      case 'Enter': {
        e.preventDefault();
        const idx = highlighted >= 0 ? highlighted : 0;
        if (suggestions[idx]) handleSelect(suggestions[idx]);
        break;
      }
      case 'ArrowDown':
        e.preventDefault();
        setHighlighted((h) => Math.min(h + 1, suggestions.length - 1));
        break;
      case 'ArrowUp':
        e.preventDefault();
        setHighlighted((h) => Math.max(h - 1, 0));
        break;
      case 'Escape':
        setOpen(false);
        break;
    }
  };

  // Scroll highlighted item into view
  useEffect(() => {
    if (highlighted >= 0 && listRef.current) {
      const el = listRef.current.children[highlighted] as HTMLElement | undefined;
      el?.scrollIntoView({ block: 'nearest' });
    }
  }, [highlighted]);

  return (
    <div className="relative">
      <input
        ref={inputRef}
        type="text"
        value={value}
        onChange={handleChange}
        onKeyDown={handleKeyDown}
        onFocus={() => { if (suggestions.length > 0) setOpen(true); }}
        onBlur={() => setTimeout(() => setOpen(false), 200)}
        placeholder={placeholder}
        className="w-full bg-slate-800 border border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-200 placeholder:text-slate-600 focus:outline-none focus:border-blue-500 font-mono"
        autoComplete="off"
        spellCheck={false}
      />
      {open && suggestions.length > 0 && (
        <ul
          ref={listRef}
          className="absolute z-50 mt-1 w-full max-h-52 overflow-auto rounded-lg border border-slate-700 bg-slate-900 shadow-xl"
        >
          {suggestions.map((entry, i) => (
            <li
              key={entry.path}
              onMouseDown={(e) => { e.preventDefault(); handleSelect(entry); }}
              onMouseEnter={() => setHighlighted(i)}
              className={`flex items-center gap-2 px-3 py-1.5 text-sm font-mono cursor-pointer transition-colors ${
                i === highlighted
                  ? 'bg-blue-500/15 text-blue-300'
                  : 'text-slate-300 hover:bg-slate-800'
              }`}
            >
              {entry.is_dir ? (
                <svg className="w-3.5 h-3.5 text-amber-400 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-6l-2-2H5a2 2 0 00-2 2z" />
                </svg>
              ) : (
                <svg className="w-3.5 h-3.5 text-slate-500 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                </svg>
              )}
              <span className="truncate">{entry.path}</span>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
