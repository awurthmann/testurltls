using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.NetworkInformation;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace testurltls
{
    class urlTest
    {
        #region Function CheckUri
        public static void CheckUri(Uri myUri, String myTls)
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
                                //var m_DestinationHost = GetPrivateField(tlsStream, "m_DestinationHost");
                                var state = GetPrivateField(tlsStream, "m_Worker");
                                var protocol = (SslProtocols)GetPrivateProperty(state, "SslProtocol");

                                if (myUri.Scheme == Uri.UriSchemeHttp)
                                {
                                    Log.WriteLog(String.Format("[INFO] Url {0} was forwarded to HTTPS", myUri.ToString()));
                                    Console.WriteLine(String.Format(" Url {0} was forwarded to ", myUri.ToString()));
                                }
                                sProtocol = protocol.ToString();
                                bHttps = true;
                            }
                            else
                            {

                            }
                        }

                    }
                    catch
                    {

                    }


                }
            }
            catch 
            { 

            }

            if (myTls == "Negotiate")
            {
                Console.WriteLine(String.Format("   Negotiated: {0}", sProtocol));
                Console.WriteLine(String.Format("   Tested {0}: {1}", sProtocol, bHttps));
                Log.WriteLog(String.Format("[INFO] Negotiated: {0}", sProtocol));
                Log.WriteLog(String.Format("[INFO] Tested {0}: {1}", sProtocol, bHttps));
            }
            else
            {
                Console.WriteLine(String.Format("   Tested {0}: {1}", myTls, bHttps));
                Log.WriteLog(String.Format("[INFO] Tested {0}: {1}", myTls, bHttps));
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
