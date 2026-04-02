import type { LanguageInfo } from '../../api/client';

const LANG_COLORS: Record<string, string> = {
  typescript: 'bg-blue-500/20 text-blue-400 border-blue-500/30',
  javascript: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
  python: 'bg-green-500/20 text-green-400 border-green-500/30',
  go: 'bg-cyan-500/20 text-cyan-400 border-cyan-500/30',
  rust: 'bg-orange-500/20 text-orange-400 border-orange-500/30',
  java: 'bg-red-500/20 text-red-400 border-red-500/30',
  ruby: 'bg-rose-500/20 text-rose-400 border-rose-500/30',
  php: 'bg-indigo-500/20 text-indigo-400 border-indigo-500/30',
  c: 'bg-gray-500/20 text-gray-400 border-gray-500/30',
  cpp: 'bg-gray-500/20 text-gray-400 border-gray-500/30',
  csharp: 'bg-violet-500/20 text-violet-400 border-violet-500/30',
  swift: 'bg-orange-500/20 text-orange-400 border-orange-500/30',
  kotlin: 'bg-purple-500/20 text-purple-400 border-purple-500/30',
  unknown: 'bg-slate-700/50 text-slate-400 border-slate-600',
};

interface LanguageBadgesProps {
  languages: LanguageInfo[];
}

export function LanguageBadges({ languages }: LanguageBadgesProps) {
  if (languages.length === 0) return null;
  return (
    <div className="flex flex-wrap gap-1.5 mt-2">
      {languages.map((lang) => (
        <span
          key={lang.language}
          className={`inline-flex items-center gap-1 px-2 py-0.5 text-xs font-medium rounded border ${
            LANG_COLORS[lang.language] ?? LANG_COLORS.unknown
          }`}
        >
          {lang.language}
          {lang.count > 1 && (
            <span className="text-[10px] opacity-70">({lang.count})</span>
          )}
        </span>
      ))}
    </div>
  );
}
