using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace testurltls
{
    class Program
    {
        static void Main(string[] args)
        {
            string url = "https://ipinfo.io/json";//Need to go find code on how to get param url
            //Also need to figure out how to pass the debug flag again and only write to log file then
            Uri myUri = new Uri(url);
            urlTest.CheckUri(myUri,"negotiate");
        }
    }
}
