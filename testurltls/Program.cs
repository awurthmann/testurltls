using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace testurltls
{
    class Program
    {
        #region Main()
        static void Main(string[] args)
        {
            string url = "Blank";
            string tls = "Negotiate";

            #region Arguments/Overrides
            if (args.Length == 1)
                ShowSyntax();

            if (args.Length >= 2 && args.Length % 2 == 0)
            {
                for (int i = 0; i < args.Length; i++)
                {
                    switch (args[i].ToString().ToLower())
                    {
                        case "-u":
                        case "-url":
                            url = args[i + 1];
                            break;
                        case "-t":
                        case "-tls":
                            tls = args[i + 1];
                            break;
                        case "/?":
                        case "-?":
                        case "-help":
                        case "-h":
                        case "/help":
                        case "/h":
                            ShowSyntax();
                            break;
                    }
                }
            }
            else
            {
                ShowSyntax();
            }
            #endregion Arguments/Overrides

            Uri myUri;
            bool isUri = Uri.TryCreate(url, UriKind.Absolute, out myUri)
                && (myUri.Scheme == Uri.UriSchemeHttp || myUri.Scheme == Uri.UriSchemeHttps);

            if (isUri)
            {
                Log.WriteLog(String.Format("[INFO] Checking Url: {0}, TLS Version: {1}",url,tls));
                Console.WriteLine(String.Format("Checking Url: {0}, TLS Version: {1}",url,tls));

                if (tls == "all")
                {
                    string[] tlses = new string[] { "Ssl3", "Tls", "Tls11", "Tls12" };
                    for (int i = 0; i < tlses.Length; i++)
                    {
                        urlTest.CheckUri(myUri, tlses[i]);
                    }
                }
                else
                {
                    urlTest.CheckUri(myUri, tls);
                }
                
            }
            else
            {
                ShowSyntax();
            }
            //Ssl3, Tls, Tls11, Tls12, Tls13 <-- Not supported
        }
        #endregion Main()

        #region ShowSyntax()
        private static void ShowSyntax()
        {
            Console.WriteLine("");
/*            Console.WriteLine("Usage: CreateHostsFile  [-dnsmode] [-pm, -premode] [-p, -pre]  [-o, -output] [-h -help]");
            Console.WriteLine("");
            Console.WriteLine("Options:");
            Console.WriteLine("    -dnsmode         Sets DNS mode to 'full', use list of global DNS servers or 'quick', skip DNS checks. Default: 'quick'");
            Console.WriteLine("    -pm or -premode  Sets previous file mode. 'all', 'settings', 'ips', Default: 'all' (both settings and IPs)");
            Console.WriteLine("    -p or -previous  [Optional] Specify non-default previous file location and filename. Default: '.\\previous_hosts.json'");
            Console.WriteLine("    -dnsfile         [Optional] Specify non-default DNS file location and filename. Default: '.\\nameserver.json'");
            Console.WriteLine("    -o or -output    [Optional] Specify non-default output location and filename. Default: '.\\hosts.json'");
            Console.WriteLine("    -h or -help      Shows these usage and syntax instructions");
            Console.WriteLine("");
            Console.WriteLine("Examples:");
            Console.WriteLine("                     CreateHostsFile.exe -m quick -o " + '"' + "test_hosts.json" + '"');
            Console.WriteLine("                     CreateHostsFile.exe -mode quick -previous" + '"' + "c:\\tmep\\previous_hosts.json" + '"');
            Console.WriteLine("");*/
            Environment.Exit(0);
        }
        #endregion ShowSyntax()
    }
}
