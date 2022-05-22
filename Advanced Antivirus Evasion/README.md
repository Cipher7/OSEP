# Intel Architecture and Windows 10

There are two primary assembly syntaxes :

- Intel
  - x86 (32-bit)
  - x86_64 (64-bit)
- AT&T

## Intel Architecture

In the Intel assembly languages, both the 32-bit and the 64-bit are quite similar at assembly level and make use of stack, heap and registers to carry out different instructions. The 64-bit version is just an extension to the 32-bit version.

Memory space supported :

32 bit - 2 GB \
64 bit - 128 TB

The registers in the 32-bit environment can be found in the below table : \

![32-bit-cpu-registers](./images/Windbg/32-bit.png)

The registers in the 64-bit environment can be found in the below table : \

![64-bit-cpu-registers](./images/Windbg/64-bit.png)

The most important registers in the 32-bit are the ESP and the EIP. They are the Stack pointer and the Instruction pointer. Their 64-bit counterparts are the RSP and the RIP.

ESP/RSP - Memory address to the top of the stack
RSP/RIP - Address of the assembly instuction to be executed.

Two types of instructions :

- Function calls
- Conditional Branching

## Intro to Windbg

Windbg can be found on the microsoft store. It supports 32-bit and 64-bit. Open notepad and start windbg

![windbg-search](./images/Windbg/windbg-search.png)

Go to File > Start Debugging > Attach to a process

![process-search](./images/Windbg/search-process.png)

Below we can see the interface with the attached process. The process execution is paused. Now let us set a breakpoint at the WriteFile Function. The breakpoint will be encountered when the process writes something to the file.

![write-file-breakpoint](./images/Windbg/create-breakpoint.png)

Now resume the execution. Write something on notepas to ttrigger the breakpoint.

![breakpoint-hit](./images/Windbg/breakpoint-hit.png)

Now we can go step-by-step to the next instruction with the 'p' command.

![move-through-instructions](./images/Windbg/move-through-instructions.png)

We can view the next 7 instructions with the 'u' command which stands for unassemble.

![view-7-instructions](./images/Windbg/view-7-instructions.png)

We can also view all the registers with the 'r' command.

![view-registers](./images/Windbg/view-registers.png)

We can get the detailed view of the registers using the dd, dc and dq command.

dd - 32 bit \
dc - 32 bit with ASCII \
dq - 64 bit

![detailed-view](./images/Windbg/detailed-view.png)

Finally we can also modify the stack with the 'ed' command.

![modify-stack](./images/Windbg/modify-stack.png)

> RESOURCES :
>
> - https://en.wikipedia.org/wiki/X86
> - https://en.wikipedia.org/wiki/Assembly_language
> - https://en.wikipedia.org/wiki/X86-64
> - https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/methods-of-controlling-breakpoints
> - https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-writefile?redirectedfrom=MSDN

&nbsp;

# AntiMalware Scan Interface
