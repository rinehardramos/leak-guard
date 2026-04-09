# leak-guard demo: selftest — all 11 checks

Output demo/selftest.gif

Set Shell "bash"
Set FontSize 14
Set Width 900
Set Height 420
Set Theme "Dracula"
Set Padding 20
Set Margin 10
Set MarginFill "#282a36"
Set BorderRadius 10
Set PlaybackSpeed 1.2

Type "# leak-guard internal smoke tests"
Enter
Sleep 300ms

Type `python3 ~/Projects/leak-guard/plugins/leak-guard/hooks/scanner.py selftest`
Sleep 300ms
Enter
Sleep 4s
