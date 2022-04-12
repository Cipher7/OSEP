# Low Level Programming Languages

Best examples are C and assembly. Code from Low level languages are converted to Opcodes through compilation process and is directly executed by the CPU. Applications written in such languages must perform their own memory management and hence are also referred as unmanaged code.

> Opcode : A Binary value which the CPU maps to a specific action

Languages like Java and C# are Object Oriented Programming Languages and compile in a much different way.

> Code > Processed by installed virtual machine > bytecode > opcodes

Java uses JVM (Java Virtual Machine), C# uses CLR (Common language runtime)

&nbsp;

# Programming Concepts

- **Class** : Templates for creating Objects
- Object is instantiated from it's class through a special method called **Contructor**
- A constructor is typically named after it's class and is used to setup and initialize the instance variable of a class
- **Modifier** : Determine the scope of a variable or method.

&nbsp;

# Windows Concepts

## Windows on Windows

Most Windows based OS are now 64-bit, but there are still some 32-bit applications.

Microsoft introduced the Windows on windows 64-bit (**WOW64**) which allows 64-bit versions of the OS to execute 32-bit application with almost zero loss in efficiency.

To facilitate translations between the 32-bit applications and the kernel, WOW64 uses four 64-bit libraries to emulate the execution of 32-bit apps. These are :

- Ntdll.dll
- Wow64.dll
- Wow64Win.dll
- Wow64Cpu.dll

On 64-bit windows, 64-bit native applications and dll's are stored in **C:\Windows\System32** while the 32-bit versions are stored in **C:\Windows\SysWOW64**.

&nbsp;

## Win32 APIs

Applications for windows can be built using various programming languages, but many of those make use of the Windows provided built-in APIs. These interfaces known as the Win32 API provide developers with pre-built functionalities.

Example:

**GetUserNameA** API exported by **Advapi32.dll** which retrieves the name of the user executing the function.

Function Prototype

    BOOL GetUserNameA(
        LPSTR lpBuffer,
        LPDWORD pcbBuffer
    );

This API requires two arguments :-

1. Output buffer of type LPSTR
2. Pointer to DWORD which is a 32-bit unsigned integer

The return value is boolean.

> Suffix "A" indicates ASCII version of the API and suffix "W" indicated the Unicode version

The Unicode version of the same code would be :-

    BOOL GetUserNameW(
        LPWSTR lpBuffer,
        LPDWORD pcbBuffer
    );

The first argument now is LPWSTR which is the Unicode character array.

&nbsp;

## Windows Registry

The registry is effectively a database that consists of a massive number of keys with associated values. These keys are sorted hierarchically using subkeys.

> **HKEY_CURRENT_USER (HKCU)** hive : Information related to current user. \
> **HKEY_LOCAL_MACHINE (HKLM)** hive : Information related to Operating System.

Note : Each hive also contains a duplicate section called Wow6432Node which stores the 32-bit settings.
