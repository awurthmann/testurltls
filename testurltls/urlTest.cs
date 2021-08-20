using System;
using System.Net;
using System.Net.Http;
using System.Reflection;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;

namespace testurltls
{
    class urlTest
    {
        #region Function CheckUri
        public static void CheckUri(Uri myUri, String myTls, String log)
        {
            bool bHttps=false;
            string sProtocol="";


            try
            {
                using (var httpClient = new HttpClient()) 
                {
                    X509Certificate2 certificate = null;
                    httpClient.Timeout = TimeSpan.FromMilliseconds(5000);
                    X509Chain certChain = new X509Chain();

                    switch (myTls)
                    {
                        case "Ssl3":
                            ServicePointManager.SecurityProtocol = SecurityProtocolType.Ssl3;
                            break;
                        case "Tls":
                            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls;
                            break;
                        case "Tls11":
                            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls11;
                            break;
                        case "Tls12":
                            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
                            break;
                        //case "Tls13":
                            //ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls13;
                            //break;
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

                    try 
                    {
                        var request = httpClient.GetAsync(myUri);
                        var response = request.Result;

                        if (response.Content is StreamContent)
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


                                if (myUri.Scheme == Uri.UriSchemeHttp)
                                {
                                    if (log == "on")
                                        Log.WriteLog(String.Format("[INFO] Url '{0}' was redirected to 'HTTPS://{1}'", myUri.ToString(), m_DestinationHost));
                                    Console.ForegroundColor = ConsoleColor.Yellow;
                                        Console.WriteLine(String.Format(" Url '{0}' was redirected to 'HTTPS://{1}'", myUri.ToString(), m_DestinationHost));
                                    Console.ResetColor();
                                }
                                else if (myUri.Host != m_DestinationHost.ToString())
                                {
                                    if (log == "on")
                                        Log.WriteLog(String.Format("[INFO] Host '{0}' was redirected to '{1}'", myUri.Host, m_DestinationHost));
                                    Console.ForegroundColor = ConsoleColor.Yellow;
                                        Console.WriteLine(String.Format(" Host '{0}' was redirected to '{1}'", myUri.Host, m_DestinationHost));
                                    Console.ResetColor();
                                }
                                sProtocol = protocol.ToString();
                                bHttps = true;
                            }
                            else
                            {
                                if (log == "on")
                                    Log.WriteLog(String.Format("[INFO] Unable to establish HTTPS session with {0}", myUri.ToString()));
                            }
                        }

                    }//End Try httpClient.GetAsync(myUri)
                    catch (Exception ex)
                    {
                        //DNS Exception
                        if (ex.InnerException.ToString().Contains("The remote name could not be resolved"))
                        {
                            Console.WriteLine(String.Format("[ERROR] Unable to resolve host '{0}'", myUri.Host));
                            if (log == "on")
                                Log.WriteLog(String.Format("[ERROR] Unable to resolve host '{0}'", myUri.Host));
                            Environment.Exit(1);
                        }
                        //Algorithm Refused
                        else if (
                            ex.InnerException.ToString().Contains("The client and server cannot communicate, because they do not possess a common algorithm") || 
                            ex.InnerException.ToString().Contains("Could not create SSL/TLS secure channel")
                            )
                        {
                            if (log == "on")
                                Log.WriteLog(String.Format("[INFO] Host '{0}' refused '{1}'", myUri.Host, myTls));
                        }
                        //Connection Refused
                        else if (ex.InnerException.ToString().Contains("No connection could be made because the target machine actively refused it"))
                        {
                            Console.WriteLine(String.Format("[ERROR] No connection could be made because {0} actively refused it", myUri.Host));
                            if (log == "on")
                                Log.WriteLog(String.Format("[ERROR] No connection could be made because {0} actively refused it", myUri.Host));
                        }
                        //Other Exception
                        else
                        {
                            if (ex.InnerException != null)
                            {
                                Console.WriteLine(String.Format("[ERROR] httpClient.GetAsync({0}), Exception was hit: {1}", myUri.ToString(), ex.InnerException));
                                if (log == "on")
                                    Log.WriteLog(String.Format("[ERROR] httpClient.GetAsync({0}), Exception was hit: {1}", myUri.ToString(), ex.InnerException));
                            }
                            else
                            {
                                Console.WriteLine(String.Format("[ERROR] httpClient.GetAsync({0}), Exception was hit: {1}", myUri.ToString(), ex.Message));
                                if (log == "on")
                                    Log.WriteLog(String.Format("[ERROR] httpClient.GetAsync({0}), Exception was hit: {1}", myUri.ToString(), ex.Message));
                            }
                        }
                    }//End Catch httpClient.GetAsync(myUri)
                }
            }//End Try httpClient = new HttpClient()
            catch (Exception ex)
            {
                Console.WriteLine(String.Format("[ERROR] Creating httpClient, CheckUri({0},{1},{3})", myUri.ToString(), myTls, log));
                if (log == "on")
                    Log.WriteLog(String.Format("[ERROR] Creating httpClient, CheckUri({0},{1},{3})", myUri.ToString(), myTls, log));

                if (ex.InnerException != null)
                {
                    Console.WriteLine(String.Format("[ERROR] CheckUri(), HttpClient Exception was hit: {0}", ex.InnerException));
                    if (log == "on")
                        Log.WriteLog(String.Format("[ERROR] CheckUri(), HttpClient Exception was hit: {0}", ex.InnerException));
                }
                else
                {
                    Console.WriteLine(String.Format("[ERROR] CheckUri(), HttpClient Exception was hit: {0}", ex.Message));
                    if (log == "on")
                        Log.WriteLog(String.Format("[ERROR] CheckUri(), HttpClient Exception was hit: {0}", ex.Message));
                }
            }//End Catch httpClient = new HttpClient()

            if (myTls == "Negotiate")
            {
                Console.WriteLine(String.Format("   Negotiated: {0}", sProtocol));
                Console.WriteLine(String.Format("   {0} Connected: {1}", sProtocol, bHttps));
                if (log == "on")
                {
                    Log.WriteLog(String.Format("[INFO] Negotiated: {0}", sProtocol));
                    Log.WriteLog(String.Format("[INFO] {0} Connected: {1}", sProtocol, bHttps));
                }
            }
            else
            {
                Console.WriteLine(String.Format("   {0} Connected: {1}", myTls, bHttps));
                if (log == "on")
                    Log.WriteLog(String.Format("[INFO] {0} Connected: {1}", myTls, bHttps));
            }
        }
        #endregion Function CheckUri

        #region Get Private Attributes
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
        #endregion Get Private Attributes
    }
}
