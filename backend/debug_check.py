import sys

path = r'F:\SentinelAI\agent\src\collector\process.rs'
with open(path, 'r') as f:
    content = f.read()

lines = content.split('\n')
for i, l in enumerate(lines):
    if any(x in l for x in ['process.cmd()', 'data: json!', 'parent_process_id', 'process_name']):
        print(f'Line {i+1}: |{l}|')
