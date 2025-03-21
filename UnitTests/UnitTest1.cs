using SapphTools.Logging;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Data.SqlClient;
using Microsoft.Extensions.Logging;
using System;
using System.IO;

namespace UnitTests {
    [TestClass]
    public class UnitTest1 {
        SapphLogger Log;
        EudLogger EudLogger;
        [TestMethod]
        public void ConstructAndInitialize() {
            string tempFolder = Path.GetTempPath();
            Log = new SapphLogger();
            EudLogger = new EudLogger();
            EudLogger.SetLoggingPath(tempFolder);
            EudLogger.Connection = new SqlConnection();
            EudLogger.LogToTS = true;
            EudLogger.LogToDB = true;
            EudLogger.LogToFile = true;
            Log.EnableDebug = false;
            Log.Log("Off domain test");
            Log.LogMode();
            EudLogger.Logger = Log;
            EudLogger.WriteData();
            Log.Log(LogLevel.None, "");
            Log.Log(EudLogger.GetJsonData());
            string finalPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments), "log.txt");
            Log.WriteFile(finalPath);
        }
    }
}
