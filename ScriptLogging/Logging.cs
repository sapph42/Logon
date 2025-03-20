using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace ScriptLogging;

#nullable enable
public class Logging {
    #region Fields
    private readonly StringBuilder logs;
    public string Logs => logs.ToString();
    #endregion
    #region Properties
    public string? LogFile { get; set; }
    #endregion
    #region ctor
    public Logging() : this(null) { }
    public Logging(string? logFile) {
        LogFile = logFile;
        logs = new(5000);
    }
    #endregion
    #region Methods
    public void Append(string LogString) => Append(LogString, true);
    public void Append(string LogString, bool IncludeDate) {
        Append(
            LogString.Split(new[] { "\r\n", "\n" }, StringSplitOptions.None),
            IncludeDate
        );
    }
    public void Append(IEnumerable<string> LogStrings) => Append(LogStrings, true);
    public void Append(IEnumerable<string> LogStrings, bool IncludeDate = true) {
        string timeStamp = IncludeDate
            ? DateTime.Now.ToString("MM/dd/yyyy HH:mm:ss.fffff") + " : "
            : "";
        foreach (string logstring in LogStrings) {
            string seperator = IncludeDate & !string.IsNullOrEmpty(logstring) ? " : " : "";
            string strToWrite = string
                .Format("{0}{1}{2}", timeStamp, seperator, logstring)
                .Replace((char)13, ' ')
                .Replace((char)10, ' ')
                .TrimEnd();
            if (string.IsNullOrWhiteSpace(strToWrite)) {
                return;
            }
            string[] linesToWrite = strToWrite.Split(new[] {"\r\n", "\n" }, StringSplitOptions.None);
            foreach (string line in linesToWrite)
                logs.AppendLine(line);
        }
    }
    public bool WriteFile() {
        if (string.IsNullOrWhiteSpace(LogFile))
            return false;
        return WriteFile(LogFile);
    }
    public bool WriteFile(string? FileName) {
        if (string.IsNullOrWhiteSpace(FileName))
            return false;
        try {
            if (!Directory.Exists(Path.GetDirectoryName(FileName))) {
                Directory.CreateDirectory(Path.GetDirectoryName(FileName));
            }
            File.WriteAllText(FileName, Logs, Encoding.UTF8);
            return true;
        } catch {
            return false;
        }
    }
    #endregion
}
#nullable disable