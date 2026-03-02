path = r'F:\SentinelAI\agent\src\collector\process.rs'
with open(path, 'r') as f:
    content = f.read()

old_block = '''                    data: json!({
                        "process_name": process.name(),
                        "process_id": pid,
                        "parent_process_id": process.parent().map(|p| p.as_u32()),
                        "command_line": process.cmd().join(" "),
                        "exe_path": process.exe().map(|p| p.to_string_lossy().to_string()),
                        "username": process.user_id().map(|u| format!("{:?}", u)),
                        "memory_bytes": process.memory(),
                        "cpu_usage": process.cpu_usage(),
                        "start_time": process.start_time(),
                        "status": format!("{:?}", process.status()),
                    }),'''

new_block = '''                    data: {
                        // Resolve parent process name for process chain detection
                        let parent_name = process.parent()
                            .and_then(|ppid| sys.process(ppid))
                            .map(|p| p.name().to_string())
                            .unwrap_or_default();

                        // cmd() can be empty on Windows; fall back to exe path
                        let cmd_line = {
                            let parts = process.cmd();
                            if parts.is_empty() {
                                process.exe()
                                    .map(|p| p.to_string_lossy().to_string())
                                    .unwrap_or_default()
                            } else {
                                parts.join(" ")
                            }
                        };

                        json!({
                            "event_type": "process",
                            "event_action": "create",
                            "process_name": process.name(),
                            "process_id": pid,
                            "parent_process_id": process.parent().map(|p| p.as_u32()),
                            "parent_process_name": parent_name,
                            "command_line": cmd_line,
                            "exe_path": process.exe().map(|p| p.to_string_lossy().to_string()),
                            "username": process.user_id().map(|u| format!("{:?}", u)),
                            "memory_bytes": process.memory(),
                            "cpu_usage": process.cpu_usage(),
                            "start_time": process.start_time(),
                            "status": format!("{:?}", process.status()),
                        })
                    },'''

if old_block in content:
    content = content.replace(old_block, new_block)
    with open(path, 'w') as f:
        f.write(content)
    print("SUCCESS: process.rs updated with parent_process_name and improved command_line")
else:
    print("ERROR: Could not find the old block. Checking...")
    # Try to find pieces
    for piece in old_block.split('\n')[:5]:
        piece = piece.strip()
        if piece and piece in content:
            print(f"  FOUND: {piece}")
        elif piece:
            print(f"  MISSING: {piece}")
