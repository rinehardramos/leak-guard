# leak-guard demo: hook protocol — secret blocked, PII asks

Output demo/hook-block.gif

Set Shell "bash"
Set FontSize 14
Set Width 900
Set Height 560
Set Theme "Dracula"
Set Padding 20
Set Margin 10
Set MarginFill "#282a36"
Set BorderRadius 10
Set PlaybackSpeed 1.2

Type "# Simulate UserPromptSubmit with a secret"
Enter
Sleep 300ms

Type `echo '{"hook_event_name":"UserPromptSubmit","prompt":"My AWS key is AKIAY3FDSNDKFKSIDJSW"}' \`
Enter
Type `  | python3 ~/Projects/leak-guard/plugins/leak-guard/hooks/scanner.py hook-user-prompt \`
Enter
Type `  | python3 -m json.tool`
Sleep 400ms
Enter
Sleep 2.5s

Type "# Simulate PreToolUse Write with a secret → denied"
Enter
Sleep 300ms

Type `echo '{"hook_event_name":"PreToolUse","tool_name":"Write","tool_input":{"file_path":"/tmp/config.py","content":"AWS_ACCESS_KEY_ID=AKIAY3FDSNDKFKSIDJSW\n"}}' \`
Enter
Type `  | python3 ~/Projects/leak-guard/plugins/leak-guard/hooks/scanner.py hook-pre-tool \`
Enter
Type `  | python3 -m json.tool`
Sleep 400ms
Enter
Sleep 2.5s

Type "# Simulate PreToolUse Bash with PII → ask dialog"
Enter
Sleep 300ms

Type `echo '{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"echo SSN: 123-45-6789"}}' \`
Enter
Type `  | python3 ~/Projects/leak-guard/plugins/leak-guard/hooks/scanner.py hook-pre-tool \`
Enter
Type `  | python3 -m json.tool`
Sleep 400ms
Enter
Sleep 2.5s

Type "# Secrets = hard block. PII = ask. Zero raw values exposed."
Enter
Sleep 800ms
