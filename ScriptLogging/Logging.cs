using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using Microsoft.Extensions.Logging;

namespace SapphTools.Logging;

#nullable enable
public class SapphLogger : ILogger {
    #region Fields
    private readonly StringBuilder logs;
    public string Logs => logs.ToString();
    #endregion
    #region Properties
    public string? LogFile { get; set; }
    public bool EnableDebug { get; set; } = false;
    #endregion
    #region ctor
    public SapphLogger() : this(null) { }
    public SapphLogger(string? logFile) {
        LogFile = logFile;
        logs = new(5000);
    }
    #endregion
    #region Methods
    private void Append(string LogString) {
        Append(
            LogString.Split(new[] { "\r\n", "\n" }, StringSplitOptions.None)
        );
    }
    private void Append(IEnumerable<string> LogStrings) {
        foreach (string logstring in LogStrings) {
            if (string.IsNullOrWhiteSpace(logstring)) {
                return;
            }
            string[] linesToWrite = logstring.Split(new[] {"\r\n", "\n" }, StringSplitOptions.None);
            foreach (string line in linesToWrite)
                logs.AppendLine(line.Trim());
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
    private void Log(string logLevel, object state, Exception? exception) {
        string dateFormatted = $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}]";
        if (state is IEnumerable<string> states && states.Count() > 1) {
            var stateList = states.ToList();
            stateList[0] = $"{logLevel} {dateFormatted} {stateList[0]}";
            Append(states);
        } else if (state is IEnumerable<string> oneState && oneState.Count() == 1) {
            string justState = oneState.First();
            Append($"{logLevel} {dateFormatted} {justState}");
        } else if (state is null) {
            Append($"{logLevel} {dateFormatted}");
        //} else if (state is FormattedLogValues vals) { 
        } else if (state is not string) {
            Append($"{logLevel} {dateFormatted}");
        } else if (state is string stateStr) {
            Append($"{logLevel} {dateFormatted} {stateStr}");
        }
        if (exception is not null) {
            Append($" -- Message\r\n{exception.Message}");
            Append($" -- Source\r\n{exception.Source}");
            Append($" -- Target Site\r\n{exception.TargetSite}");
            Append($" -- Stack Trace\r\n{exception.StackTrace}");
        }
    }
    public void Log(string message) => Log(LogLevel.Information, message, null);
    public void Log(string message, Exception? exception) => Log(LogLevel.Information, message, exception);
    public void Log(LL logLevel, string message) => Log((LogLevel)(int)logLevel, message);
    public void Log(LogLevel logLevel, string message) => Log(logLevel, message, null);
    public void Log(LL logLevel, string message, Exception? exception) => Log((LogLevel)(int)logLevel, message, exception);
    public void Log(LogLevel logLevel, string message, Exception? exception) {
        Log(logLevel, new EventId(), message, exception, (message, exception) => "");
    }
    public void Log(LogLevel logLevel, EventId _1, string message, Exception? exception, Func<string, Exception?, string> _2) {
        if (logLevel == LogLevel.None) {
            if (message is string blank && string.IsNullOrWhiteSpace(blank))
                Append("");
            return;
        }

        int logLevelWidth = 12; // Choose a fixed width for uniformity
        string logLevelFormatted = FormatLogLevel(logLevel, logLevelWidth);

        if (exception is not null) {
            // Always reflect exceptions in logLevelFormatted
            logLevelFormatted = (logLevel == LogLevel.Debug || EnableDebug)
                                ? FormatLogLevel("Debug/Error", logLevelWidth)
                                : FormatLogLevel("Error", logLevelWidth);
            if (logLevel == LogLevel.Debug && EnableDebug)
                Log(logLevelFormatted, message, exception);
            else if (EnableDebug) {
                Log(FormatLogLevel(LogLevel.Error, logLevelWidth), message, null);
                Append(exception.Message);
            } else if (logLevel == LogLevel.Debug) {
                Log(logLevelFormatted, message, null);
                Append(exception.Message);
            }

        } else {
            // If Debug and EnableDebug, ensure Debug/Error gets logged correctly
            if (logLevel == LogLevel.Debug && EnableDebug) {
                logLevelFormatted = FormatLogLevel("Debug/Error", logLevelWidth);
            }

            Log(logLevelFormatted, message, null);
        }
    }
    public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter) {
        Log(logLevel, state?.ToString() ?? "", exception);
    }
    public void LogMode() {
        Log(LogLevel.Information, $"Full debuging enabled: {EnableDebug}");
    }
    public bool IsEnabled(LogLevel logLevel) {
        return logLevel switch {
            LogLevel.Information or LogLevel.Error or 
                LogLevel.Warning or LogLevel.Debug or
                LogLevel.None => true,
            _ => false,
        };
    }
    public IDisposable? BeginScope<TState>(TState state) where TState : notnull {
        string message = $"{state} Begin";
        Console.WriteLine(message);
        Append(message);
        return new DisposableScope(() => Append($"{state} End"));
    }
    private string FormatLogLevel(string logLevel, int width) {
        return $"[{logLevel.PadLeft((width + logLevel.Length) / 2).PadRight(width)}]";
    }
    private string FormatLogLevel(LogLevel logLevel, int width) => FormatLogLevel(logLevel.ToString(), width);
    private class DisposableScope : IDisposable {
        private readonly Action _onDispose;
        public DisposableScope(Action onDispose) => _onDispose = onDispose;
        public void Dispose() => _onDispose();
    }
    #endregion
}