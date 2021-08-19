using System;
using System.IO;
using System.Threading;
//using System.Collections.Generic;
//using System.Linq;
//using System.Text;
//using System.Threading.Tasks;


namespace testurltls
{
    class Log
    {
        static ReaderWriterLock locker = new ReaderWriterLock();
        public static void WriteLog(string LogDataToWrite)
        {
            string myLogLineToWrite = ($"{DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss")}: " + LogDataToWrite);

            try
            {
                locker.AcquireWriterLock(int.MaxValue);
                System.IO.File.AppendAllLines(Path.Combine(Path.GetDirectoryName(System.Reflection.Assembly.GetExecutingAssembly().GetName().CodeBase).Replace("file:\\", ""), "log.txt"), new[] { myLogLineToWrite });
            }
            finally
            {
                locker.ReleaseWriterLock();
            }
        }
    }
}
