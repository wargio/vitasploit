vitasploit
==========

This project is yet another Vita exploitation solution for the recent WebKit vulnerability that allows exploring the native part of the Vita's software.

The vitasploit project is merely a continuation of Amat Cama, johntheropper and freebot's amazing work who presented a complete solution for memory reading/writing and code execution using ROP for the Vita.

Dependencies
============

Python2: https://www.python.org/downloads/

Capstone: http://www.capstone-engine.org/download.html

Instructions
============

Start up the server by running the `server.py` script. Using your Vita browse to the address printed by the script (`http://<ipaddr>:8888`).

**Memory reading/writing mode:**
- In the main html file (`index.html`) set `initMemoryHole(false)`;
- With this setting the script will launch an interactive shell for memory reading/writing;
- Commands:
  - `read <addr> <len>` -> Read "len" bytes from "addr" (the output is printed to the shell)
  - `disasm <addr> <len> <mode>` -> Disassemble "len" bytes at "addr" with "mode" (mode can be "arm" or "thumb)
  - `dump <addr> <len> <outfile>` -> Dump "len" bytes from "addr" to "outfile" (dumped files are saved under "dumps" folder)
  - `ss <beginaddr> <endaddr> <pattern>` -> Search for string "pattern" from "beginaddr" to "endaddr"
  - `scanm <beginaddr>` -> Scan for modules starting at "beginaddr"
  - `dispx <beginaddr> <n>` -> Display <n> module exports starting at "beginaddr"
  - `dispim <beginaddr> <n>` -> Display <n> module imports starting at "beginaddr"
  - `dispminf <beginaddr>` -> Display module info starting at "beginaddr"
  - `scanback <begaddr> <step>` -> Scan back memory until it crashes starting at "beginaddr" using "step"
  - `reload` -> Reload the interactive shell
  - `help` -> Print the available commands and their syntax
  - `exit` -> Terminate the interactive shell

**ROP mode:**
- In the main html file (`index.html`) set `initMemoryHole(true)`;
- With this setting the script will launch a pre-programmed, firmware dependent, ROP chain;
- You can use the functions availabe at `include/samples.js` to interact in a SDK-like fashion with the Vita;
- The functions are called from the `include/exploit.js` file. Simply uncomment them and modify as you wish;
- The following tests are currently implemented for firmwares 3.00, 3.15 and 3.18:
  - `Module dumping test` -> Based on CodeLion/BrianBTB/BBalling1's module dumping code and complemented by nas's sysmodule loading code. Forces all user modules to be loaded into memory and dumps them to "dumps" folder
  - `Memory test` -> A simple memory alloc/free test using the SceLibKernel syscalls
  - `Socket connection test` -> Original (akai) socket test to send messages to/from the Vita
  - `Directory listing test` -> Original (akai) test to list directories inside the Vita
  - `File retrieval test` -> Original (akai) test to find and dump user files from the Vita
    
Credits
=======

- **Amat Cama**, **johntheropper** and **freebot**: Original Vita exploit toolkit/SDK code (https://github.com/acama/webkitties);
- **CodeLion/BrianBTB/BBalling1**: Original PoC, module dumping code and other utilities (https://github.com/BrianBTB/memtools_vita and https://github.com/BrianBTB/JSoS-Module-Dump-Release);
- **nas**: sceSysmoduleLoadModule finding (http://pastie.org/private/ugchhaqctvmw5rrg5w37ka);
- **Davee**, **Josh_Axey** and **Archaemic**: Individual PoC code to showcase this vulnerability;
- **Yifan Lu**: UVLoader source code and extensive documentation on the Vita (http://yifan.lu/);
- **mr.gas**, **tomtomdu80** and **YANOX**: Several findings and reverse-engineer works on the Vita;
- **BlackDaemon**: Testing.
