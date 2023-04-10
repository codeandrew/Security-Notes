# Shellcodes

Shellcodes are sequences of machine code instructions typically used in exploits to perform a specific action, such as opening a remote shell, launching a specific program, or downloading and executing a file. They are often used in conjunction with buffer overflow attacks or other types of vulnerabilities that allow an attacker to inject and execute arbitrary code on a target system.

Shellcodes are usually crafted in assembly language and then converted to machine code. The shellcode must be small, efficient, and compatible with the target architecture, such as x86, x64, or ARM. Additionally, they must avoid null bytes or other problematic characters that could cause issues during execution.

To execute a shellcode, an attacker would typically exploit a vulnerability to gain control over the instruction pointer (EIP) in a target process. The attacker then redirects the EIP to the memory location where the shellcode has been injected. Upon execution, the shellcode performs the desired action.

Some common purposes of shellcodes include:

- Reverse shell: Opens a remote shell back to the attacker's machine, allowing the attacker to execute commands on the target system.
- Bind shell: Listens for incoming connections on a specific port and spawns a shell for the connecting party.
- Download and execute: Downloads a file from a remote server and executes it on the target system.

Here's a simple example of a shellcode that spawns a shell (/bin/sh) on a Unix-like system:

```asm
xor eax, eax
push eax
push 0x68732f2f
push 0x6e69622f
mov ebx, esp
push eax
push ebx
mov ecx, esp
mov al, 11
int 0x80
```

This shellcode sets up the required arguments for the execve system call to execute "/bin/sh" and then triggers the system call using int 0x80. Please note that the provided example is for educational purposes only and should not be used for malicious activities.

Let's break down the assembly code I provided earlier, which spawns a shell (/bin/sh) on Unix-like systems:

```asm
xor eax, eax         ; Clear the eax register by XORing it with itself
push eax            ; Push a null byte (0x00) onto the stack as a string terminator
push 0x68732f2f     ; Push the string "//sh" onto the stack in little-endian format
push 0x6e69622f     ; Push the string "/bin" onto the stack in little-endian format
mov ebx, esp        ; Move the stack pointer (esp) to ebx, pointing it to the string "/bin//sh"
push eax            ; Push a null byte (0x00) onto the stack as the argv terminator
push ebx            ; Push the address of the "/bin//sh" string onto the stack
mov ecx, esp        ; Move the stack pointer (esp) to ecx, pointing it to the argv array
mov al,
```



