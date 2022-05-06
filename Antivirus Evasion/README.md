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

To split the binary, we can use the powershell tool **Find-AVSignature**. Example command :-

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
    $bytes[6969] = 0
    [System.IO.File]::WriteAllBytes("mal_mod.exe", $bytes)

Explanation :

- Suppose at byte 6969, the AV was getting triggered.
- We would first convert the whole binary into bytes and store it in a variable
- We then would replace the location with a 0
- Now we would write the bytes into a new file
- Splitting and passing this through clamscan again, the byte would not trigger the AV.

&nbsp;

# Bypassing AV with Metasploit
