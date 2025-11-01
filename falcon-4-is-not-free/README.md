# Chapter 4: Is not free (5 points)

Hi, emergency troubleshooter,

recent studies suggest that the intense heat and hard labor of solar
technicians often trigger strange, vivid dreams about the future of energetics.
Over the past few days, technicians have woken up night after night with the
same terrifying screams "Look, up in the sky! It’s a bird! It’s a plane! It’s
Superman! Let’s roast it anyway!".

Find out what’s going on, we need our technicians to stay sane.

Stay grounded!

* http://intro.falcon.powergrid.tcc/

## Hints

* Be sure you enter flag for correct chapter.
* In this realm, challenges should be conquered in a precise order, and to
  triumph over some, you'll need artifacts acquired from others - a unique
  twist that defies the norms of typical CTF challenges.
* Chapter haiku will lead you.

## Solution

We're already familiar with FALCON chapter carousel from [Chapter 1: Operator][ch1]

The fourth haiku says:

```text
Respect the craft’s birth,
Code is earned, not taken swift —
Licence guards its worth.
```

The title leads to http://thevendor.falcon.powergrid.tcc/#firmware, i.e. to
the XWiki we've already seen in [Chapter 2][ch2]. The anchor also suggests
the firmware (downloaded in the same chapter) and haiku points to licence
guards.

Using a disassembler (see [Chapter 3][ch3]) and/or AI analysis on the
[firmware][fw] binary, we can identify several functions:

- `licence1` (0x29f8) - Character conversion function
- `licence2` (0x2ada) - Hex string to binary conversion
- `licence3` (0x129c) - String processing
- `licence4` (0x1234) - Buffer transformation
- `licence5` (0x11d2) - Final processing

Analyzing the `processVERSCommand` function (0x2b3a), we discover that it:

1. Allocates a 26-byte buffer using `malloc()`
2. Copies **25 bytes** from flash memory at address **0x0143**
3. Processes this data through all five license functions

The 25-byte length matches the expected flag format `FLAG{xxxx-xxxx-xxxx-xxxx}`
so we can guess this might be the flag we're looking for.

Examining the flash memory at 0x0143:
```
5a 15 33 9d e0 ba 71 21 cb 05 6a 8a ca 36 b2 99 0a fb 23 9a 17 c9 57 29 96
```

This does not look like the flag yet. It seems this somehow encrypted data gets
transformed through the license functions into the plaintext flag. Even the
chapter name (very subtly) indicates that something (the flag?) is not free, so
exploring the memory buffer that is being `free`'d sounds like a sensible path.

The license functions are triggered when the firmware processes the `VERS`
command (version query). The execution flow is:

```
processCommand() → processVERSCommand() → licence1-5() → FLAG revealed?
```

Let's try to do the following:
1. Run the firmware in a simulator (`simavr`)
2. Inject the VERS command into the command buffer
3. Use GDB to trace execution and inspect memory
4. Read the decrypted flag from the buffer before it's freed

The following script automates the entire process using `simavr` and `avr-gdb`.

To be precise, the script will:

1. Start the AVR simulator with GDB support
2. Initialize firmware and wait for main loop
3. Inject `VERS` command into the command buffer (0x8004d8)
4. Set command length to 4 (0x8004ed)
5. Set command ready flag to 1 (0x8004f0) - this triggers `processCommand()`
6. Track the `malloc`'d buffer containing the 25-byte block
7. Execute through all license transformation functions
8. Display the decrypted flag before the buffer is `free`'d

```bash
#!/bin/bash
# Check copied data and show final result before free()

# Start simavr in background with GDB server
echo "[*] Starting simavr with GDB server..."
simavr -m atmega328p -f 16000000 -g roostguard-firmware-0.9.bin &
SIMAVR_PID=$!

# Wait for simavr to start
sleep 2

# Create GDB command script
cat > /tmp/gdb_step_trace.gdb << 'EOF'
# Connect to simavr
target remote :1234

set pagination off
set confirm off

# Initialize variable
set $license_buffer = 0

# Set temporary breakpoint in main loop
tbreak *0x31aa
continue

# Inject VERS command
set {unsigned char}0x8004d8 = 'V'
set {unsigned char}0x8004d9 = 'E'
set {unsigned char}0x8004da = 'R'
set {unsigned char}0x8004db = 'S'
set {unsigned char}0x8004dc = 0

# commandLen - length of "VERS"
set {unsigned char}0x8004ed = 4
# commandReady - flag to trigger processing
set {unsigned char}0x8004f0 = 1

printf "[*] VERS command injected\n"

# Break at processVERSCommand entry
tbreak *0x2b3a
continue
printf "[*] At processVERSCommand\n"

# Break after malloc returns (buffer allocated)
tbreak *0x2b52
continue

# Capture the buffer address with SRAM offset for GDB
set $license_buffer = 0x800000 + (($r25 << 8) | $r24)
printf "[*] Buffer allocated at GDB address: 0x%06x\n", $license_buffer

# Continue to after the 25 bytes are copied from flash
tbreak *0x2b64
continue

printf "\n========================================================\n"
printf "DATA COPIED - Verification we're checking correct buffer\n"
printf "========================================================\n"
printf "Expected: 5a 15 33 9d e0 ba 71 21 cb 05 6a 8a ca...\n"
printf "Actual:   "
x/25xb $license_buffer
printf "\n"

# Set breakpoint at free() - check if it's our buffer
break *0x35b0
commands
  silent
  set $free_addr = 0x800000 + (($r25 << 8) | $r24)
  if $free_addr == $license_buffer
    printf "\n========================================\n"
    printf "BEFORE free() - FINAL BUFFER STATE\n"
    printf "========================================\n"
    printf "Address: 0x%06x\n", $license_buffer
    printf "\nHEX:\n"
    x/25xb $license_buffer
    printf "\nSTRING:\n"
    x/s $license_buffer
    printf "\nASCII:\n"
    x/25c $license_buffer
    printf "\n========================================\n"
    continue
  else
    continue
  end
end

printf "\n[*] Continuing execution until buffer is freed...\n"
continue

EOF

# Run GDB in batch mode
echo "[*] Running avr-gdb..."
avr-gdb -batch -x /tmp/gdb_step_trace.gdb roostguard-firmware-0.9.bin

# Cleanup
kill $SIMAVR_PID 2>/dev/null
rm /tmp/gdb_step_trace.gdb
```

Running the script now reveals the flag

```
$ chmod +x showflag.sh
$ ./showflag.sh
[*] Starting simavr with GDB server...
Loaded 17156 .text at address 0x0
Loaded 398 .data
avr_gdb_init listening on port 1234
[*] Running avr-gdb...
gdb_network_handler connection opened
0x00000000 in __vectors ()
Temporary breakpoint 1 at 0x31aa
Note: automatically using hardware breakpoints for read-only addresses.

Temporary breakpoint 1, 0x000031aa in main ()
[*] VERS command injected
Temporary breakpoint 2 at 0x2b3a

Temporary breakpoint 2, 0x00002b3a in processVERSCommand() ()
[*] At processVERSCommand
Temporary breakpoint 3 at 0x2b52

Temporary breakpoint 3, 0x00002b52 in processVERSCommand() ()
[*] Buffer allocated at GDB address: 0x80055c
Temporary breakpoint 4 at 0x2b64

Temporary breakpoint 4, 0x00002b64 in processVERSCommand() ()

========================================================
DATA COPIED - Verification we're checking correct buffer
========================================================
Expected: 5a 15 33 9d e0 ba 71 21 cb 05 6a 8a ca...
Actual:   0x80055c:     0x5a    0x15    0x33    0x9d    0xe0    0xba    0x71    0x21
0x800564:       0xcb    0x05    0x6a    0x8a    0xca    0x36    0xb2    0x99
0x80056c:       0x0a    0xfb    0x23    0x9a    0x17    0xc9    0x57    0x29
0x800574:       0x96

Breakpoint 5 at 0x35b0

[*] Continuing execution until buffer is freed...

========================================
BEFORE free() - FINAL BUFFER STATE
========================================
Address: 0x80055c

HEX:
0x80055c:       0x46    0x4c    0x41    0x47    0x7b    0x4b    0x66    0x63
0x800564:       0x50    0x2d    0x48    0x65    0x5a    0x51    0x2d    0x6c
0x80056c:       0x75    0x4b    0x59    0x2d    0x6d    0x49    0x78    0x42
0x800574:       0x7d

STRING:
0x80055c:       "FLAG{KfcP-HeZQ-luKY-mIxB}"

ASCII:
0x80055c:       70 'F'  76 'L'  65 'A'  71 'G'  123 '{' 75 'K'  102 'f' 99 'c'
0x800564:       80 'P'  45 '-'  72 'H'  101 'e' 90 'Z'  81 'Q'  45 '-'  108 'l'
0x80056c:       117 'u' 75 'K'  89 'Y'  45 '-'  109 'm' 73 'I'  120 'x' 66 'B'
0x800574:       125 '}'

========================================
```

[ch1]: ../falcon-1-operator
[ch2]: ../falcon-2-the-vendor
[ch3]: ../falcon-3-open-the-door
[fw]: https://github.com/jandurovec/the-catch-2025/raw/refs/heads/main/falcon-2-the-vendor/roostguard-firmware-0.9.zip
