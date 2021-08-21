using System;

//  Microsoft Visual Studio Community 2019, Version: 16.9.3
//  Microsoft Windows Version 10.0.19042.1165
//  .NET Framework 4.6.1

namespace testurltls
{
    #region Program Class
    class Program
    {
        #region Main()
        static void Main(string[] args)
        {
            string url = "Blank";
            string tls = "Negotiate";
            bool log = false;
            bool warning = true;
            bool quiet = false;

            #region Arguments/Overrides
            if (args.Length == 1)
                url = args[0].ToString();

            else if (args.Length >= 2 && args.Length % 2 == 0)
            {
                for (int i = 0; i < args.Length; i++)
                {
                    switch (args[i].ToString().ToLower())
                    {
                        case "/u":
                        case "-u":
                        case "-url":
                            url = args[i + 1];
                            break;
                        case "/t":
                        case "-t":
                        case "-tls":
                            tls = args[i + 1];
                            break;
                        case "/l":
                        case "-l":
                        case "-log":
                            if (string.Equals(args[i + 1], (string)"true",StringComparison.OrdinalIgnoreCase) ||
                                    string.Equals(args[i + 1], (string)"on", StringComparison.OrdinalIgnoreCase))
                                log = true;
                            break;                        
                        case "/q":
                        case "-q":
                        case "-quiet":
                            if (string.Equals(args[i + 1], (string)"true",StringComparison.OrdinalIgnoreCase) ||
                                    string.Equals(args[i + 1], (string)"on", StringComparison.OrdinalIgnoreCase))
                                quiet = true;
                            break;
                        case "/w":
                        case "-w":
                        case "-warning":
                            if (string.Equals(args[i + 1], (string)"false", StringComparison.OrdinalIgnoreCase) ||
                                    string.Equals(args[i + 1], (string)"off", StringComparison.OrdinalIgnoreCase))
                                warning = false;
                            break;
                        case "/?":
                        case "-?":
                        case "-help":
                        case "-h":
                        case "/help":
                        case "/h":
                            ShowSyntax();
                            break;
                        case "/a":
                        case "-a":
                        case "-about":
                            if (string.Equals(args[i + 1], (string)"true", StringComparison.OrdinalIgnoreCase) || 
                                    string.Equals(args[i + 1], (string)"on", StringComparison.OrdinalIgnoreCase))
                                ShowAbout();
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
                if (!quiet)
                    Console.WriteLine(String.Format("Checking Url: {0}, TLS Version: {1}",url,tls));
                if (log)
                    Log.WriteLog(String.Format("[INFO] Checking Url: {0}, TLS Version: {1}", url, tls));

                if (tls == "all" && quiet == false)
                {
                    string[] tlses = new string[] { "Ssl3", "Tls", "Tls11", "Tls12" };
                    for (int i = 0; i < tlses.Length; i++)
                        urlTest.CheckUri(myUri, tlses[i], log, warning, quiet);
                }
                else
                    urlTest.CheckUri(myUri, tls, log, warning, quiet);
            }
            else
                ShowSyntax();
        }
        #endregion Main()

        #region ShowSyntax()
        private static void ShowSyntax()
        {
            Console.WriteLine("");
            Console.WriteLine("Usage: testurltls.exe  [-url, -u] [-tls, -t] [-h -help]");
            Console.WriteLine("");
            Console.WriteLine("Options:");
            Console.WriteLine("    -url or -u       [REQUIRED] Url to connect to");
            Console.WriteLine("    -tls or -t       [OPTIONAL] Specify protocol or 'all', Default: Negotiate");
            Console.WriteLine("                         Supported protocols: Ssl3, Tls, Tls11, Tls12");
            Console.WriteLine("    -log or -l       [OPTIONAL] 'on'|'off' Turns log to file on or off, Default: 'off'");
            Console.WriteLine("    -warning or -w   [OPTIONAL] 'on'|'off' Turns redirect warning on or off, Default: 'on'");
            Console.WriteLine("    -quiet or -q     [OPTIONAL] 'on'|'off' Enables quiet mode, Default: 'off'");
            Console.WriteLine("                         Quiet mode returns only the result 'True'|'False'");
            Console.WriteLine("                          '-tls all' is ignored in quiet mode, -warning is set to 'off'");
            Console.WriteLine("    -h or -help      Shows these usage and syntax instructions");
            Console.WriteLine("");
            Console.WriteLine("Examples:");
            Console.WriteLine("                     testurltls.exe -url https://www.google.com");
            Console.WriteLine("                     testurltls.exe -url https://www.google.com -tls all");
            Console.WriteLine("                     testurltls.exe -url https://www.google.com -tls Ssl3");
            Console.WriteLine("");
            Environment.Exit(0);
        }
        #endregion ShowSyntax()

        #region ShowAboutx()
        private static void ShowAbout()
        {
            Console.WriteLine("");
            Console.WriteLine("About: testurltls.exe (Test Turtles)");
            Console.WriteLine("     _____     ____	     _____     ____	");
            Console.WriteLine("    / 8  8 \\  |  O |	    / 8  8 \\  |  O |");
            Console.WriteLine("   |8  8  8 |/ ____|	   |8  8  8 |/ ____|");
            Console.WriteLine("   |_8___8___/		   |_8___8___/");
            Console.WriteLine("^^^|_|_| |_|_|^^^^^^^^^^^^^|_|_| |_|_|^^^^^^^");
            Console.WriteLine("");
            Console.WriteLine("Orginal Author: Aaron Wurthmann");
            Console.WriteLine("URL: https://github.com/awurthmann/testurltls");
            Console.WriteLine("");
            Console.WriteLine("Tested on:");
            Console.WriteLine("     Microsoft Windows [Version 10.0.19042.1165]");
            Console.WriteLine("                            .NET Framework 4.6.1");
            Console.WriteLine("");
            Environment.Exit(0);
        }
        #endregion ShowAbout()
    }
    #endregion Program Class
}
