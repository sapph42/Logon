using System;
using System.Data.SqlClient;
using System.IO;
using Microsoft.Extensions.Logging;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SapphTools.Logging;

namespace UnitTests {
    [TestClass]
    public class UnitTest1 {
        SapphLogger Log;
        EudLogger EudLogger;
        [TestMethod]
        public void ConstructAndInitialize() {
            string tempFolder = Path.GetTempPath();
            Log = new SapphLogger();
            Log.Log("Test Initialized");
            EudLogger = new EudLogger();
            EudLogger.SetLoggingPath(tempFolder);
            EudLogger.Connection = new SqlConnection();
            EudLogger.LogToTS = true;
            EudLogger.LogToDB = true;
            EudLogger.LogToFile = true;
            Log.EnableDebug = false;
            Log.Log("Off domain test");
            Log.LogMode();
            EudLogger.Logger = new SapphLogger();
            EudLogger.WriteData();
            Log.Log(LogLevel.None, "");
            Log.Merge(EudLogger.Logger);
            string finalPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments), "log.txt");
            Log.WriteFile(finalPath);
        }
    }
}
