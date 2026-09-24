import re
from pathlib import Path

p = Path('radar/web/static/presentation.html')
text = p.read_text(encoding='utf-8')

start_marker = '<!-- SLIDE 2: Problem -->'
end_marker = '</main>'
start_idx = text.index(start_marker)
end_idx = text.index(end_marker)
head, body, tail = text[:start_idx], text[start_idx:end_idx], text[end_idx:]

replacements = [
    (r'bg-slate-900/60', 'glass'),
    (r'bg-slate-900/80', 'glass-strong'),
    (r'bg-slate-900/90', 'glass-strong'),
    (r'bg-slate-900\b', 'glass'),
    (r'bg-slate-950\b', 'bg-black/30'),
    (r'bg-slate-800/60\b', 'bg-white/10'),
    (r'bg-slate-800/50\b', 'bg-white/10'),
    (r'bg-slate-800/40\b', 'bg-white/5'),
    (r'bg-slate-800\b', 'bg-white/10'),
    (r'border-slate-800\b', 'border-white/10'),
    (r'border-slate-700\b', 'border-white/15'),
    (r'bg-red-950/20', 'bg-rose-500/10'),
    (r'bg-red-950/30', 'bg-rose-500/10'),
    (r'bg-red-950\b', 'bg-rose-500/15'),
    (r'border-red-900/30', 'border-rose-400/30'),
    (r'border-red-900/40', 'border-rose-400/30'),
    (r'border-red-900\b', 'border-rose-400/40'),
    (r'text-red-400\b', 'text-rose-300'),
    (r'bg-red-900/50', 'bg-rose-500/20'),
    (r'bg-amber-950/20', 'bg-amber-400/10'),
    (r'bg-amber-950/30', 'bg-amber-400/10'),
    (r'border-amber-900/30', 'border-amber-300/30'),
    (r'border-amber-900/40', 'border-amber-300/30'),
    (r'text-amber-400\b', 'text-amber-300'),
    (r'bg-amber-900/50', 'bg-amber-400/20'),
    (r'bg-orange-950/30', 'bg-orange-400/10'),
    (r'border-orange-900/40', 'border-orange-300/30'),
    (r'text-orange-400\b', 'text-orange-300'),
    (r'bg-blue-950/30', 'bg-cyan-400/10'),
    (r'bg-blue-950/40', 'bg-cyan-400/10'),
    (r'border-blue-900/40', 'border-cyan-300/30'),
    (r'border-blue-900/30', 'border-cyan-300/30'),
    (r'border-blue-800\b', 'border-cyan-300/40'),
    (r'text-blue-400\b', 'text-cyan-300'),
    (r'text-blue-300\b', 'text-cyan-200'),
    (r'bg-blue-600\b', 'bg-gradient-to-r from-violet-600 to-fuchsia-500'),
    (r'bg-blue-500/20', 'bg-cyan-400/15'),
    (r'bg-blue-500\b', 'bg-cyan-400'),
    (r'bg-indigo-950/40', 'bg-violet-400/10'),
    (r'border-indigo-800\b', 'border-violet-300/40'),
    (r'text-indigo-400\b', 'text-violet-300'),
    (r'bg-indigo-400\b', 'bg-violet-400'),
    (r'from-blue-500', 'from-violet-500'),
    (r'to-indigo-500', 'to-fuchsia-500'),
    (r'bg-emerald-950/30', 'bg-emerald-400/10'),
    (r'border-emerald-900/40', 'border-emerald-300/30'),
    (r'text-emerald-400\b', 'text-emerald-300'),
    (r'bg-emerald-500/20', 'bg-emerald-400/15'),
    (r'border-emerald-500/30', 'border-emerald-400/30'),
    (r'bg-emerald-500\b', 'bg-emerald-400'),
]

for pat, repl in replacements:
    body = re.sub(pat, repl, body)

text = head + body + tail
p.write_text(text, encoding='utf-8')
print('done, length', len(text))
