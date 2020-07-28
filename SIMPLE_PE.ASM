format PE GUI at 0xfe0000

include 'win32ax.inc'

.code

  start:
        invoke  MessageBox,HWND_DESKTOP,"Hi! I'm the example program!",invoke GetCommandLine,MB_OK
        invoke  ExitProcess,0

.end start

section '.reloc' fixups data readable discardable       ; needed for Win32s