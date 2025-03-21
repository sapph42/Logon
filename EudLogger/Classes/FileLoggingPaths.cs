using System.IO;

namespace SapphTools.Logging;

#nullable enable
public struct FileLoggingPaths {
    public string? MachineLogs;
    public string? MachineStats;
    public string? UserLogon;
    public string? ComputerLogon;
    public string? DebugLogs;
    public string? AppLogs;
    public string? PrinterLogs;
    public string? StatLogs;
    public string Cache = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "LLT");
    public FileLoggingPaths() { }
}