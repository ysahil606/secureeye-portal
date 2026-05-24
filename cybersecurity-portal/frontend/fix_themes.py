import re

css_path = r'c:\Users\Sahil\Dropbox\My PC (LAPTOP-MQVV34RN)\Desktop\secureeye-portal\cybersecurity-portal\frontend\src\index.css'
with open(css_path, 'r', encoding='utf-8') as f:
    css = f.read()

def hex_to_rgb(hex_str):
    hex_str = hex_str.lstrip('#')
    if len(hex_str) == 6:
        return f"{int(hex_str[0:2], 16)} {int(hex_str[2:4], 16)} {int(hex_str[4:6], 16)}"
    return hex_str

vars_to_convert = [
    '--bg-app', '--bg-panel', '--bg-card', '--bg-card-hover', '--border-light', 
    '--text-muted', '--text-dim', '--accent-primary', '--accent-secondary'
]

def replace_var_def(match):
    var_name = match.group(1)
    hex_val = match.group(2)
    if var_name in vars_to_convert:
        return f"{var_name}: {hex_to_rgb(hex_val)};"
    return match.group(0)

css = re.sub(r'(--[a-zA-Z0-9-]+):\s*(#[a-fA-F0-9]{6});', replace_var_def, css)

def replace_var_usage(match):
    pre = match.group(1)
    var_name = match.group(2)
    # If the usage is already rgb(var(...)), do not wrap it again!
    if "rgb" in pre:
        return match.group(0)
    
    if var_name in vars_to_convert:
        return f"{pre}rgb(var({var_name}))"
    return match.group(0)

css = re.sub(r'([^\w-]*\s*)var\((--[a-zA-Z0-9-]+)\)', replace_var_usage, css)

with open(css_path, 'w', encoding='utf-8') as f:
    f.write(css)

print("index.css updated to use RGB format for tailwind opacity support.")
