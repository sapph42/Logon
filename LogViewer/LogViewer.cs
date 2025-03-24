using System;
using System.Collections.Generic;
using System.Data;
using System.Diagnostics;
using System.Drawing;
using System.Globalization;
using System.Linq;
using System.Text.RegularExpressions;
using System.Windows.Forms;

namespace LogViewer {
    public partial class LogViewer: Form {
        public LogViewer() {
            InitializeComponent();
        }
        private void LogViewer_Load(object sender, EventArgs e) {
            string rawLog = testing;
            List<StructuredLog> logs = GetStructuredLogs(rawLog);
            foreach (var log in logs) {
                var row = new DataGridViewRow();
                row.CreateCells(LogDgv);
                row.Cells[0].Value = log.Type;
                row.Cells[1].Value = log.Timestamp.ToString();
                row.Cells[2].Value = log.Log;
                switch (log.Type) {
                    case string s when s.Contains("Error"):
                    case string ss when ss.Contains("Debug") && log.Log.Contains("\n") :
                        row.Cells.Cast<DataGridViewCell>().ToList().ForEach(c => c.Style.BackColor = Color.Red);
                        row.Cells.Cast<DataGridViewCell>().ToList().ForEach(c => c.Style.ForeColor = Color.White);
                        break;
                    case string s when s.Contains("Debug"):
                    case string ss when ss.Contains("Warning"):
                        row.Cells.Cast<DataGridViewCell>().ToList().ForEach(c => c.Style.BackColor = Color.Goldenrod);
                        break;
                }
                row.Cells[2].Style.WrapMode = DataGridViewTriState.True;
                LogDgv.Rows.Add(row);
            }
            Debug.WriteLine(logs.Count);
        }
        private static List<StructuredLog> GetStructuredLogs(string RawLog) {
            List<StructuredLog> logs = new List<StructuredLog>();
            StructuredLog currentChunk = null;

            foreach (string line in RawLog.Split(new[] { "\r\n", "\n" }, StringSplitOptions.None)) {
                var match = Regex.Match(line, @"(?:\[)(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{4})(?:\])");
                if (match.Success) {
                    currentChunk = new StructuredLog(line);
                    logs.Add(currentChunk);
                } else {
                    currentChunk?.AppendLine(line);
                }
            }
            return logs;
        }


        private class StructuredLog {
            public string Type { get; internal set; }
            public DateTime Timestamp { get; internal set; }
            public string Log { get; internal set; }
            internal StructuredLog(string UnstructuredLog) {
                Regex regex = new Regex(@"(?:\[)(.{12})(?:\])(?:\s*)(?:\[)(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{4})(?:\])(?:\s*)(.*)");
                var match = regex.Match(UnstructuredLog);
                if (match.Success) {
                    Type = match.Groups[1].Value;
                    Timestamp = DateTime.ParseExact(
                        match.Groups[2].Value,
                        "yyyy-MM-dd HH:mm:ss.ffff",
                        CultureInfo.InvariantCulture
                    );
                    Log = match.Groups[3].Value;
                }
            }
            public void AppendLine(string line) {
                line = line.Trim();
                if (line == @"""")
                    return;
                Log += Environment.NewLine + line;
            }
        }
        private const string testing = @"[Information ] [2025-03-22 13:07:25.0697] nickgibson
[Information ] [2025-03-22 13:07:25.0697] VIRTUALPHOENIX
[Information ] [2025-03-22 13:07:25.0697] Script Start - v3.4.0
[Information ] [2025-03-22 13:07:25.0697] Environment: Implementing functions
[Information ] [2025-03-22 13:07:25.0697] Environment: Preference structure
[Information ] [2025-03-22 13:07:25.0710] Environment: Loaded preference file to memory
[Information ] [2025-03-22 13:07:25.0710] Environment: Generated simple variables from preferences
[Information ] [2025-03-22 13:07:25.0710] Environment: Generated data structures from preferences
[Information ] [2025-03-22 13:07:25.0710] GenerateSQLConnection: Begin
[Information ] [2025-03-22 13:07:25.0710] GenerateSQLConnection: Sucessfully instantiated SQLConnection object
[  Warning   ] [2025-03-22 13:07:25.0858] CheckForAlert: Unjoined machine
[Information ] [2025-03-22 13:07:25.0918] PIV Check: Starting check
[Debug/Error ] [2025-03-22 13:07:25.0918] PIV Check: Check failed
Exception calling ""FindOne"" with ""0"" argument(s): ""The specified domain either does not exist or could not be contacted.
""
[Information ] [2025-03-22 13:07:25.1016] WriteAdapterData: Trasmitting AdapterData to DB
[Information ] [2025-03-22 13:07:25.1016] AdapterData: Count: 3
[Debug/Error ] [2025-03-22 13:07:39.3335] AdapterData: failed to open connection.
A network-related or instance-specific error occurred while establishing a connection to SQL Server. The server was not found or was not accessible. Verify that the instance name is correct and that SQL Server is configured to allow remote connections. (provider: Named Pipes Provider, error: 40 - Could not open a connection to SQL Server)
[Information ] [2025-03-22 13:07:39.3335] WriteAdapterData: Transmission of adapter data failed. No further DB attempts will be made. Caching enabled.
[Information ] [2025-03-22 13:07:39.3335] WriteLoginData: Logging not skipped by TS or logging options
[Information ] [2025-03-22 13:07:39.3444] GetOneDriveStatus: False
[Information ] [2025-03-22 13:07:39.3444] WriteLoginData: Writing LoginData to File
[Information ] [2025-03-22 13:07:39.3701] WriteLoginData: Trasmitting LoginData to DB
[Information ] [2025-03-22 13:07:39.3701] WriteStatData: Logging not skipped by TS or logging options
[Information ] [2025-03-22 13:07:39.3701] StatData: BIOS data cached in registry. Skipping Win32_Bios
[Information ] [2025-03-22 13:07:39.3701] StatData: Fetching CPU Count from Windows API
[Information ] [2025-03-22 13:07:39.3701] StatData: Fetching CPU data from Registry
[Information ] [2025-03-22 13:07:39.3701] StatData: Fetching RAM from Windows API
[Information ] [2025-03-22 13:07:39.3701] StatData: Fetching HDD data from Windows API
[Information ] [2025-03-22 13:07:39.3932] StatData: Active BT Radios 1
[   Error    ] [2025-03-22 13:07:39.3932] Failed to retrieve TPM version. Result: -2144845820
[Information ] [2025-03-22 13:07:39.3932] StatData: TPM Version Detected As: Unk
[Information ] [2025-03-22 13:07:39.3932] WriteStatData: Writing StatData to File
[Information ] [2025-03-22 13:07:39.4030] WriteAppData: Writing AppData to file
[Debug/Error ] [2025-03-22 13:07:39.4125] AppData: File write failed.
Could not find a part of the path 'C:\Mac\Home\Documents\LLTTest\PCINFO\LOGS\VIRTUALPHOENIX.Applications.csv'.

[Information ] [2025-03-22 13:07:39.4202] MapAllDrives: Begin
[Information ] [2025-03-22 13:07:39.4202] MapAllDrives: GlobalMaps
[Information ] [2025-03-22 13:07:39.4242] MapDrive: Begin attempt to map \\EAMCFS01\dept$\_EAMC_Data\Medical Photos
[Information ] [2025-03-22 13:07:42.1201] MapDrive: Function exited.  User does not have rights to \\EAMCFS01\dept$\_EAMC_Data\Medical Photos
[Information ] [2025-03-22 13:07:42.1201] MapDrive: Begin attempt to map \\EAMCFS01\dept$\_EAMC_Data\public
[Information ] [2025-03-22 13:07:42.1201] MapDrive: Function exited.  User does not have rights to \\EAMCFS01\dept$\_EAMC_Data\public
[Information ] [2025-03-22 13:07:42.1201] MapDrive: Begin attempt to map \\EAMCFS01\dept$\_EAMC_Data\helpdesk
[Information ] [2025-03-22 13:07:42.1221] MapDrive: Function exited.  User does not have rights to \\EAMCFS01\dept$\_EAMC_Data\helpdesk
[Information ] [2025-03-22 13:07:42.1262] ProfileRedirection: OneDrivePath C:\Users\nickgibson\OneDrive - militaryhealth
[  Warning   ] [2025-03-22 13:07:42.1262] ProfileRedirection: OneDrivePath Not Detected
[Information ] [2025-03-22 13:07:42.1262] ProfileRedirection: Setting Keys At HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders
[Information ] [2025-03-22 13:07:42.1322] ProfileRedirection: Setting Keys At HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders
[Information ] [2025-03-22 13:07:42.1380] ProfileRediction: Modified user shell folders
[Information ] [2025-03-22 13:07:42.1400] IndividualFileManagement: Removing hard coded files
[Information ] [2025-03-22 13:07:42.1400] Environment: Writing fastlog

";
    }
}
