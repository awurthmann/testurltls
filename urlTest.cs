using System;
using System.Net;
using System.Net.Http;
using System.Reflection;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;

namespace testurltls
{
    #region urlTest Class
    class urlTest
    {
        #region Function CheckUri()
        public static void CheckUri(Uri myUri, string myTls, bool log, bool warning, bool quiet)
        {
            bool bHttps=false;
            string sProtocol="";

            #region HttpClient
            try
            {
                using (var httpClient = new HttpClient()) 
                {
                    X509Certificate2 certificate = null;
                    httpClient.Timeout = TimeSpan.FromMilliseconds(5000);
                    X509Chain certChain = new X509Chain();

                    switch (myTls)
                    {
                        case "ssl3":
                        case "Ssl3":
                            ServicePointManager.SecurityProtocol = SecurityProtocolType.Ssl3;
                            break;
                        case "tls":
                        case "Tls":
                        case "tls1":
                        case "Tls1":
                            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls;
                            break;
                        case "tls11":
                        case "Tls11":
                            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls11;
                            break;
                        case "tls12":
                        case "Tls12":
                            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
                            break;
                        //case "tls13": //Unsupported in .NET Framework
                        //case "Tls13":
                        //    ServicePointManager.SecurityProtocol = (SecurityProtocolType)12288; 
                        //    break;
                        default:
                            myTls = "Negotiate";
                            break;
                    }

                    ServicePointManager.ServerCertificateValidationCallback += (sender, cert, chain, sslPolicyErrors) =>
                    {
                        bool result = false;
                        certificate = new X509Certificate2(cert.GetRawCertData());
                        if (certificate != null)
                            result = true;

                        return result;
                    };

                    #region GetAsync()
                    try
                    {
                        var request = httpClient.GetAsync(myUri);
                        var response = request.Result;

                        if (response.StatusCode != HttpStatusCode.Forbidden && response.Content is StreamContent)
                        {
                            var webExceptionWrapperStream = GetPrivateField(response.Content, "content");
                            var connectStream = GetBasePrivateField(webExceptionWrapperStream, "innerStream");
                            var connection = GetPrivateProperty(connectStream, "Connection");
                            var tlsStream = GetPrivateProperty(connection, "NetworkStream");

                            if (tlsStream.ToString() == "System.Net.TlsStream")
                            {
                                var m_DestinationHost = GetPrivateField(tlsStream, "m_DestinationHost");
                                var state = GetPrivateField(tlsStream, "m_Worker");
                                var protocol = (SslProtocols)GetPrivateProperty(state, "SslProtocol");
                                string absoluteUri = response.RequestMessage.RequestUri.AbsoluteUri;

                                if (myUri.ToString() != absoluteUri)
                                {
                                    if (log)
                                        Log.WriteLog(String.Format("[INFO] Url '{0}' was redirected to '{1}'", myUri.ToString(), absoluteUri));
                                    if (warning && !quiet)
                                    {
                                        Console.ForegroundColor = ConsoleColor.Yellow;
                                            Console.WriteLine(String.Format(" Url '{0}' was redirected to '{1}'", myUri.ToString(), absoluteUri));
                                        Console.ResetColor();
                                    }

                                }
                                else if (myUri.Host != m_DestinationHost.ToString())
                                {
                                    if (log)
                                        Log.WriteLog(String.Format("[INFO] Host '{0}' was redirected to '{1}'", myUri.Host, m_DestinationHost));
                                    if (warning && !quiet)
                                    {
                                        Console.ForegroundColor = ConsoleColor.Yellow;
                                            Console.WriteLine(String.Format(" Host '{0}' was redirected to '{1}'", myUri.Host, m_DestinationHost));
                                        Console.ResetColor();
                                    }

                                }
                                sProtocol = protocol.ToString();
                                bHttps = true;
                            }
                            else
                            {
                                if (log)
                                    Log.WriteLog(String.Format("[INFO] Unable to establish HTTPS session with {0}", myUri.ToString()));
                            }
                        }
                        else
                        {
                            if (response.StatusCode != null)
                            {
                                if (!quiet)
                                    Console.WriteLine(String.Format("Returned status code {0},{1}", (int)response.StatusCode, response.StatusCode));
                                if (log)
                                    Log.WriteLog(String.Format("[INFO] Returned status code {1},{2}", myUri.ToString(), (int)response.StatusCode, response.StatusCode));

                                if ((response.StatusCode == HttpStatusCode.Forbidden) && (myTls == "Negotiate" || string.Equals(myTls, (string)"tls12", StringComparison.OrdinalIgnoreCase)))
                                {
                                    if (!quiet)
                                        Console.WriteLine(String.Format("May require TLS 1.3, currently unsupported by application", myUri.ToString()));
                                    if (log)
                                        Log.WriteLog(String.Format("[INFO] {0} may require TLS 1.3, currently unsupported by application", myUri.ToString()));
                                }
                            }
                        }

                    }//End Try httpClient.GetAsync(myUri)
                    catch (Exception ex)
                    {
                        //DNS Exception
                        if (ex.InnerException.ToString().Contains("The remote name could not be resolved"))
                        {
                            if (!quiet)
                                Console.WriteLine(String.Format("ERROR: Unable to resolve host '{0}'", myUri.Host));
                            if (log)
                                Log.WriteLog(String.Format("[ERROR] Unable to resolve host '{0}'", myUri.Host));
                            Environment.Exit(1);
                        }
                        //Algorithm Refused
                        else if (
                            ex.InnerException.ToString().Contains("The client and server cannot communicate, because they do not possess a common algorithm") || 
                            ex.InnerException.ToString().Contains("Could not create SSL/TLS secure channel")
                            )
                        {
                            if (log)
                                Log.WriteLog(String.Format("[INFO] Host '{0}' refused '{1}'", myUri.Host, myTls));
                        }
                        //Outbound Refused
                        else if (
                            ex.InnerException.ToString().Contains("An attempt was made to access a socket in a way forbidden by its access permissions"))
                        {
                            if (!quiet)
                                Console.WriteLine(String.Format("[ERROR] Outbound connection forbidden by access permissions"));
                            if (log)
                                Log.WriteLog(String.Format("[ERROR] Outbound connection forbidden by access permissions"));
                        }                        
                        //Connection Refused
                        else if (
                            ex.InnerException.ToString().Contains("No connection could be made because the target machine actively refused it") ||
                            ex.InnerException.ToString().Contains("The underlying connection was closed")
                            )
                        {
                            if (!quiet)
                                Console.WriteLine(String.Format("[ERROR] No connection could be made because {0} actively refused it", myUri.Host));
                            if (log)
                                Log.WriteLog(String.Format("[ERROR] No connection could be made because {0} actively refused it", myUri.Host));
                        }
                        //Other Exception
                        else
                        {
                            if (ex.InnerException != null)
                            {
                                if (!quiet)
                                    Console.WriteLine(String.Format("[ERROR] httpClient.GetAsync({0}), Exception was hit. InnerException: {1}", myUri.ToString(), ex.InnerException));
                                if (log)
                                    Log.WriteLog(String.Format("[ERROR] httpClient.GetAsync({0}), Exception was hit. InnerException: {1}", myUri.ToString(), ex.InnerException));
                            }
                            else
                            {
                                if (!quiet)
                                    Console.WriteLine(String.Format("[ERROR] httpClient.GetAsync({0}), Exception was hit. Exception Message: {1}", myUri.ToString(), ex.Message));
                                if (log)
                                    Log.WriteLog(String.Format("[ERROR] httpClient.GetAsync({0}), Exception was hit. Exception Message: {1}", myUri.ToString(), ex.Message));
                            }
                        }
                    }//End Catch httpClient.GetAsync(myUri)
                    #endregion GetAsync()

                    httpClient.Dispose();
                }
                
            }//End Try httpClient = new HttpClient()
            catch (Exception ex)
            {
                //if (ex is FormatException || System.Net.WebException)
                //{
                //    Console.WriteLine("Hit here");
                //}
                Console.WriteLine("Hit here");

                Console.WriteLine(String.Format("[ERROR] Creating httpClient, CheckUri({0},{1},{3})", myUri.ToString(), myTls, log));
                if (log)
                    Log.WriteLog(String.Format("[ERROR] Creating httpClient, CheckUri({0},{1},{3})", myUri.ToString(), myTls, log));

                if (ex.InnerException != null)
                {
                    Console.WriteLine(String.Format("[ERROR] CheckUri(), HttpClient Exception was hit. InnerException: {0}", ex.InnerException));
                    if (log)
                        Log.WriteLog(String.Format("[ERROR] CheckUri(), HttpClient Exception was hit. InnerException: {0}", ex.InnerException));
                }
                else
                {
                    Console.WriteLine(String.Format("[ERROR] CheckUri(), HttpClient Exception was hit. Exception Message: {0}", ex.Message));
                    if (log)
                        Log.WriteLog(String.Format("[ERROR] CheckUri(), HttpClient Exception was hit. Exception Message: {0}", ex.Message));
                }

            }//End Catch httpClient = new HttpClient()
            #endregion HttpClient

            #region Output
            //Connected
            if (sProtocol != null && sProtocol != "")
            {
                string sExpandedTls = ExpandTlsVersion(sProtocol);
                int iTlsVersion = NumericTlsVersion(sProtocol);

                if (myTls == "Negotiate")
                {
                    if (quiet)
                    {
                        Console.WriteLine(bHttps);
                    }
                    else
                    {
                        Console.WriteLine(String.Format("Negotiated: {0}", sExpandedTls));
                        Console.WriteLine(String.Format("{0} Connected: {1}", sExpandedTls, bHttps));
                    }

                    if (log)
                    {
                        Log.WriteLog(String.Format("[INFO] Negotiated: {0}", sProtocol));
                        Log.WriteLog(String.Format("[INFO] {0} Connected: {1}", sProtocol, bHttps));
                    }

                    Environment.Exit(iTlsVersion);
                }
                else
                {
                    if (quiet)
                        Console.WriteLine(bHttps);
                    else
                        Console.WriteLine(String.Format("{0} Connected: {1}", ExpandTlsVersion(myTls), bHttps));

                    if (log)
                        Log.WriteLog(String.Format("[INFO] {0} Connected: {1}", ExpandTlsVersion(myTls), bHttps));

                    Environment.Exit(iTlsVersion);
                }
            }
            //Unable to Connect
            else
            {
                string sExpandedTls = ExpandTlsVersion(myTls);
                int iTlsVersion = NumericTlsVersion(myTls);

                if (quiet)
                {
                    Console.WriteLine(bHttps);
                }
                else if (myTls == "Negotiate")
                {
                    Console.WriteLine(String.Format("Negotiated: {0}", bHttps));
                    if (log)
                        Log.WriteLog(String.Format("[INFO] Negotiated: {0}", bHttps));
                }
                else
                {
                    Console.WriteLine(String.Format("{0} Connected: {1}", sExpandedTls, bHttps));
                    if (log)
                        Log.WriteLog(String.Format("[INFO] {0} Connected: {1}", sExpandedTls, bHttps));
                }
                Environment.Exit(iTlsVersion);
            }
            #endregion Output
        }
        #endregion Function CheckUri()

        #region Get Private Attributes Functions
        private static object GetPrivateProperty(object obj, string property)
        {
            return obj.GetType().GetProperty(property, BindingFlags.Instance | BindingFlags.NonPublic).GetValue(obj);
        }

        private static object GetPrivateField(object obj, string field)
        {
            return obj.GetType().GetField(field, BindingFlags.Instance | BindingFlags.NonPublic).GetValue(obj); //
        }

        private static object GetBasePrivateField(object obj, string field)
        {
            return obj.GetType().BaseType.GetField(field, BindingFlags.Instance | BindingFlags.NonPublic).GetValue(obj);
        }
        #endregion Get Private Attributes Functions

        #region ExpandTlsVersion()
        private static string ExpandTlsVersion(string tls)
        {
            switch (tls.ToLower())
            {
                case "ssl3":
                    return "SSL 3.0";
                case "tls":
                case "tls1":
                    return "TLS 1.0";
                case "tls11":
                    return "TLS 1.1";
                case "tls12":
                    return "TLS 1.2";
                //case "tls13":
                //    return "TLS 1.3";
                default:
                    return "ERROR";
            }
        }
        #endregion ExpandTlsVersion()

        #region NumericTlsVersion()
        private static int NumericTlsVersion(string tls)
        {
            switch (tls.ToLower())
            {
                case "ssl3":
                    return 3;
                case "tls":
                case "tls1":
                    return 10;
                case "tls11":
                    return 11;
                case "tls12":
                    return 12;
                //case "tls13":
                //    return 13;
                default:
                    return 1;
            }
        }
        #endregion NumericTlsVersion()

    }
    #endregion urlTest Class
}
