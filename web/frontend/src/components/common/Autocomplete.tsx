import { useCallback, useEffect, useRef, useState } from 'react';

interface AutocompleteProps {
  value: string;
  onChange: (val: string) => void;
  suggestions: string[];
  placeholder?: string;
  className?: string;
  /** Secondary text shown to the right of each suggestion */
  secondaryText?: (item: string) => string | undefined;
  /** When true, an empty query shows all suggestions on focus */
  showAllOnFocus?: boolean;
}

export function Autocomplete({
  value,
  onChange,
  suggestions,
  placeholder,
  className,
  secondaryText,
  showAllOnFocus = true,
}: AutocompleteProps) {
  const [open, setOpen] = useState(false);
  const [highlighted, setHighlighted] = useState(-1);
  const inputRef = useRef<HTMLInputElement>(null);
  const listRef = useRef<HTMLUListElement>(null);

  const filtered = value
    ? suggestions.filter((s) => s.toLowerCase().includes(value.toLowerCase()))
    : showAllOnFocus
      ? suggestions
      : [];

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    onChange(e.target.value);
    setOpen(true);
    setHighlighted(-1);
  };

  const handleSelect = useCallback(
    (item: string) => {
      onChange(item);
      setOpen(false);
      setHighlighted(-1);
      inputRef.current?.focus();
    },
    [onChange],
  );

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (!open || filtered.length === 0) {
      if (e.key === 'ArrowDown' || e.key === 'Tab') {
        if (filtered.length > 0 || (showAllOnFocus && suggestions.length > 0)) {
          setOpen(true);
          setHighlighted(0);
          if (e.key === 'Tab') e.preventDefault();
        }
        return;
      }
      return;
    }

    switch (e.key) {
      case 'Tab':
      case 'Enter': {
        e.preventDefault();
        const idx = highlighted >= 0 ? highlighted : 0;
        if (filtered[idx]) handleSelect(filtered[idx]);
        break;
      }
      case 'ArrowDown':
        e.preventDefault();
        setHighlighted((h) => Math.min(h + 1, filtered.length - 1));
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

  useEffect(() => {
    if (highlighted >= 0 && listRef.current) {
      const el = listRef.current.children[highlighted] as HTMLElement | undefined;
      el?.scrollIntoView({ block: 'nearest' });
    }
  }, [highlighted]);

  const baseClass =
    'w-full bg-slate-800 border border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-200 placeholder:text-slate-600 focus:outline-none focus:border-blue-500';

  return (
    <div className="relative">
      <input
        ref={inputRef}
        type="text"
        value={value}
        onChange={handleChange}
        onKeyDown={handleKeyDown}
        onFocus={() => {
          if (showAllOnFocus && suggestions.length > 0) setOpen(true);
        }}
        onBlur={() => setTimeout(() => setOpen(false), 200)}
        placeholder={placeholder}
        className={className ?? baseClass}
        autoComplete="off"
        spellCheck={false}
      />
      {open && filtered.length > 0 && (
        <ul
          ref={listRef}
          className="absolute z-50 mt-1 w-full max-h-52 overflow-auto rounded-lg border border-slate-700 bg-slate-900 shadow-xl"
        >
          {filtered.map((item, i) => {
            const secondary = secondaryText?.(item);
            return (
              <li
                key={item}
                onMouseDown={(e) => {
                  e.preventDefault();
                  handleSelect(item);
                }}
                onMouseEnter={() => setHighlighted(i)}
                className={`flex items-center justify-between px-3 py-1.5 text-sm cursor-pointer transition-colors ${
                  i === highlighted
                    ? 'bg-blue-500/15 text-blue-300'
                    : 'text-slate-300 hover:bg-slate-800'
                }`}
              >
                <span className="truncate font-mono">{item}</span>
                {secondary && (
                  <span className="text-xs text-slate-500 ml-2 flex-shrink-0">{secondary}</span>
                )}
              </li>
            );
          })}
        </ul>
      )}
    </div>
  );
}
