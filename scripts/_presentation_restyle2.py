import re
from pathlib import Path

p = Path('radar/web/static/presentation.html')
text = p.read_text(encoding='utf-8')

text = text.replace('border-l-4 border-blue-500', 'border-l-4 border-fuchsia-400')
text = re.sub(
    r'class="text-3xl md:text-4xl font-bold text-white mb-6"',
    'class="font-display text-3xl md:text-4xl font-bold text-white mb-6"',
    text,
)

p.write_text(text, encoding='utf-8')
print('ok')
