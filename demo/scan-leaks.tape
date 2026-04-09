# leak-guard demo: on-demand scanner
# Shows /scan-leaks finding secrets and PII in fixture files

Output demo/scan-leaks.gif

Set Shell "bash"
Set FontSize 14
Set Width 900
Set Height 500
Set Theme "Dracula"
Set Padding 20
Set Margin 10
Set MarginFill "#282a36"
Set BorderRadius 10
Set PlaybackSpeed 1.2

# Start with a clean prompt
Type "# leak-guard: on-demand scanner demo"
Enter
Sleep 500ms

Type "# Scan a file containing a fake AWS key"
Enter
Sleep 300ms

Type `python3 ~/Projects/leak-guard/plugins/leak-guard/hooks/scanner.py scan-path ~/Projects/leak-guard/tests/fixtures/fake_aws.txt`
Sleep 300ms
Enter
Sleep 2s

Type "# Scan a file containing PII (SSN, email, phone, credit card)"
Enter
Sleep 300ms

Type `python3 ~/Projects/leak-guard/plugins/leak-guard/hooks/scanner.py scan-path ~/Projects/leak-guard/tests/fixtures/fake_pii.txt`
Sleep 300ms
Enter
Sleep 2s

Type "# Clean file → no findings, exit 0"
Enter
Sleep 300ms

Type `python3 ~/Projects/leak-guard/plugins/leak-guard/hooks/scanner.py scan-path ~/Projects/leak-guard/tests/fixtures/clean.txt`
Sleep 300ms
Enter
Sleep 1.5s

Type "# Raw values are NEVER shown — only redacted previews"
Enter
Sleep 500ms
