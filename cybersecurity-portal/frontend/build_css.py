import re
import sys

css_path = r'c:\Users\Sahil\Dropbox\My PC (LAPTOP-MQVV34RN)\Desktop\secureeye-portal\cybersecurity-portal\frontend\src\index.css'
with open(css_path, 'r', encoding='utf-8') as f:
    css = f.read()

theme_vars = '''
:root, [data-theme="cyber-default"] {
  --bg-app: #020617;
  --bg-panel: #0a0e1a;
  --bg-card: #0f172a;
  --bg-card-hover: #151e32;
  --border-light: #1e293b;
  --text-muted: #334155;
  --text-dim: #475569;
  --text-main: #f1f5f9;
  
  --accent-primary: #3b82f6;
  --accent-secondary: #a855f7;
  --bg-mesh: radial-gradient(at 40% 20%, hsla(280,100%,74%,0.15) 0px, transparent 50%), radial-gradient(at 80% 0%, hsla(189,100%,56%,0.15) 0px, transparent 50%), radial-gradient(at 0% 50%, hsla(355,100%,93%,0) 0px, transparent 50%);
  --neon-glow-pri: rgba(59, 130, 246, 0.5);
  --neon-glow-sec: rgba(168, 85, 247, 0.5);
}

[data-theme="neon-hacker"] {
  --bg-app: #000000;
  --bg-panel: #050505;
  --bg-card: #0a0f0a;
  --bg-card-hover: #101810;
  --border-light: #142414;
  --text-muted: #1e3b1e;
  --text-dim: #2d5a2d;
  --text-main: #39ff14;
  
  --accent-primary: #39ff14;
  --accent-secondary: #00ff00;
  --bg-mesh: radial-gradient(at 50% 50%, rgba(57, 255, 20, 0.05) 0px, transparent 70%);
  --neon-glow-pri: rgba(57, 255, 20, 0.6);
  --neon-glow-sec: rgba(0, 255, 0, 0.6);
}

[data-theme="red-team"] {
  --bg-app: #0a0202;
  --bg-panel: #140505;
  --bg-card: #1c0a0a;
  --bg-card-hover: #2a0f0f;
  --border-light: #3d1414;
  --text-muted: #4a1c1c;
  --text-dim: #6b2828;
  --text-main: #ffebeb;
  
  --accent-primary: #ff003c;
  --accent-secondary: #ff3333;
  --bg-mesh: radial-gradient(at 20% 80%, rgba(255, 0, 60, 0.1) 0px, transparent 60%);
  --neon-glow-pri: rgba(255, 0, 60, 0.6);
  --neon-glow-sec: rgba(255, 51, 51, 0.6);
}

[data-theme="blue-team"] {
  --bg-app: #000c18;
  --bg-panel: #001529;
  --bg-card: #002240;
  --bg-card-hover: #003366;
  --border-light: #004d99;
  --text-muted: #005cbf;
  --text-dim: #007bff;
  --text-main: #e6f2ff;
  
  --accent-primary: #00bfff;
  --accent-secondary: #00f2fe;
  --bg-mesh: radial-gradient(at 80% 20%, rgba(0, 191, 255, 0.1) 0px, transparent 60%);
  --neon-glow-pri: rgba(0, 191, 255, 0.6);
  --neon-glow-sec: rgba(0, 242, 254, 0.6);
}

[data-theme="vaporwave"] {
  --bg-app: #120024;
  --bg-panel: #1a0033;
  --bg-card: #28004d;
  --bg-card-hover: #3d007a;
  --border-light: #5c00b3;
  --text-muted: #7a00e6;
  --text-dim: #9933ff;
  --text-main: #ffccff;
  
  --accent-primary: #ff00ff;
  --accent-secondary: #00ffff;
  --bg-mesh: radial-gradient(at 30% 30%, rgba(255, 0, 255, 0.15) 0px, transparent 50%), radial-gradient(at 70% 70%, rgba(0, 255, 255, 0.15) 0px, transparent 50%);
  --neon-glow-pri: rgba(255, 0, 255, 0.6);
  --neon-glow-sec: rgba(0, 255, 255, 0.6);
}

[data-theme="stealth-mode"] {
  --bg-app: #0a0a0a;
  --bg-panel: #121212;
  --bg-card: #1a1a1a;
  --bg-card-hover: #242424;
  --border-light: #333333;
  --text-muted: #4d4d4d;
  --text-dim: #808080;
  --text-main: #cccccc;
  
  --accent-primary: #a3a3a3;
  --accent-secondary: #737373;
  --bg-mesh: none;
  --neon-glow-pri: rgba(163, 163, 163, 0.3);
  --neon-glow-sec: rgba(115, 115, 115, 0.3);
}

[data-theme="midnight-gold"] {
  --bg-app: #000b18;
  --bg-panel: #001226;
  --bg-card: #001a33;
  --bg-card-hover: #002b5e;
  --border-light: #003a80;
  --text-muted: #4a4a4a;
  --text-dim: #b89742;
  --text-main: #fcf1d4;
  
  --accent-primary: #ffc107;
  --accent-secondary: #ff9800;
  --bg-mesh: radial-gradient(at 50% 10%, rgba(255, 193, 7, 0.08) 0px, transparent 60%);
  --neon-glow-pri: rgba(255, 193, 7, 0.6);
  --neon-glow-sec: rgba(255, 152, 0, 0.6);
}

[data-theme="cyberpunk-city"] {
  --bg-app: #12042b;
  --bg-panel: #1c083d;
  --bg-card: #280a52;
  --bg-card-hover: #370e70;
  --border-light: #4c139c;
  --text-muted: #6220b8;
  --text-dim: #8843e6;
  --text-main: #fcee21;
  
  --accent-primary: #fcee21;
  --accent-secondary: #f00eb5;
  --bg-mesh: radial-gradient(at 10% 90%, rgba(240, 14, 181, 0.15) 0px, transparent 50%), radial-gradient(at 90% 10%, rgba(252, 238, 33, 0.15) 0px, transparent 50%);
  --neon-glow-pri: rgba(252, 238, 33, 0.6);
  --neon-glow-sec: rgba(240, 14, 181, 0.6);
}
'''

if 'var(--bg-app)' not in css:
    css = css.replace('@tailwind utilities;', '@tailwind utilities;\n\n' + theme_vars)

    css = re.sub(
        r'body\s*\{[^}]*\}', 
        '''body {
  background-color: var(--bg-app);
  background-image: var(--bg-mesh);
  background-attachment: fixed;
  @apply text-slate-100 min-h-screen;
  margin: 0;
  transition: background-color 0.5s ease, background-image 0.5s ease;
}''', 
        css, 
        flags=re.MULTILINE
    )

    css = re.sub(
        r'select option\s*\{[^}]*\}',
        '''select option {
  background-color: var(--bg-card);
  color: var(--text-main);
  padding: 8px;
}''', css
    )
    css = re.sub(
        r'select optgroup\s*\{[^}]*\}',
        '''select optgroup {
  background-color: var(--bg-app);
  color: var(--accent-primary);
  font-weight: bold;
}''', css
    )

    css = css.replace('hover:shadow-[0_0_15px_rgba(59,130,246,0.5)]', 'hover:shadow-[0_0_15px_var(--neon-glow-pri)]')
    css = css.replace('hover:border-blue-500/30', 'hover:border-accent-primary/30')

    css = re.sub(
        r'\.btn-primary\s*\{\s*@apply\s+bg-gradient-to-r\s+from-blue-600\s+to-purple-600\s+hover:from-blue-500\s+hover:to-purple-500\s+text-white\s+font-bold\s+px-6\s+py-2\.5\s+rounded-xl\s+transition-all\s+shadow-lg\s+hover:shadow-neon-purple([^}]*)\}',
        '.btn-primary { @apply bg-gradient-to-r from-accent-primary to-accent-secondary text-white font-bold px-6 py-2.5 rounded-xl transition-all shadow-lg disabled:opacity-50 disabled:cursor-not-allowed; box-shadow: 0 4px 15px rgba(0,0,0,0.3); }\n  .btn-primary:hover:not(:disabled) { box-shadow: 0 0 15px var(--neon-glow-sec); opacity: 0.9; transform: translateY(-1px); }',
        css
    )

    with open(css_path, 'w', encoding='utf-8') as f:
        f.write(css)
    print("CSS updated successfully")
else:
    print("CSS already contains dynamic variables.")
