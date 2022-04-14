using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Windows.Forms;
[ComVisible(true)]
public class TestClass
{   
    public TestClass()
    {
        MessageBox.Show("Test", "Test", MessageBoxButtons.OK, MessageBoxIcon.Exclamation);
    }
     public void RunProcess(string path)
    {
        Process.Start(path);
    }
}