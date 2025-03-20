using System.Data.SqlClient;
using System.Runtime.CompilerServices;
using System.Text.RegularExpressions;
using ScriptLogging;
using System.Net.NetworkInformation;
using System.IO;
using System.Printing;
using Microsoft.Win32;
using System.Management;
using Windows.Devices.Radios;
using System.Text;
using System.Collections;
using System.Diagnostics;
using System.Text.Json;

#nullable enable
namespace EudLogger; 
public class EudLogger {
    #region Constants

    #endregion
    #region Fields
    private readonly AdapterCollection _adapterData  = new();
    private readonly AppCollection     _appData      = new();
    private readonly string            _computerName = Environment.MachineName;
    private FileLoggingPaths           _logPaths     = new();
    private readonly LoginData         _loginData    = new();
    private readonly PrinterCollection _printerData  = new();
    private readonly StatData          _statData     = new();
    private Regex                      _terminalServer;
    public  Logging                    Logger        = new();
    public bool                        CacheNeeded   => _loginData.ToCache && _statData.ToCache && _adapterData.ToCache;
    public string?                     JsonCache     = null;
    #endregion
    #region Properties
    public SqlConnection? Connection { get; set; }
    public string? DebugLogFile {
        get => Logger.LogFile;
        set => Logger.LogFile = value;
    }
    public string Exception = "";
    public bool ODStatus = false;
    public bool LogToDB { get; set; }
    public bool LogToFile { get; set; }
    public bool LogToTS { get; set; }
    public string SiteCode;
    #endregion
    #region ctor
    public EudLogger(string SiteCode) {
        this.SiteCode = SiteCode;
        SetTerminalServer(SiteCode);
        string? logonserver = Environment.GetEnvironmentVariable("logonserver");
        if (!string.IsNullOrEmpty(logonserver)) {
            try {
                _loginData.DC.Value = System.Net.Dns.GetHostEntry(logonserver.Replace("\\", "")).HostName;
            } catch (Exception ex) {
                Logger.Append($"Meta: Failed to get FQDN for logonserver. {ex.Message}");
            }
        }
    }
    #endregion
    #region Private Methods
    #region Utility Methods
    [MemberNotNull(nameof(_terminalServer))]
    private void SetTerminalServer(string siteCode) {
        _terminalServer = new(@$"^{siteCode}TS.*$");
    }
    private bool TsCheck([CallerMemberName]string caller = "") {
        if (!LogToTS && _terminalServer.IsMatch(_computerName)) {
            Logger.Append($"{caller}: Logging skipped due to Terminal Server rule");
            return true;
        }
        return false;
    }
    #endregion
    #region SQL Helper Methods
    private SqlCommand? BuildAdapterCommand() {
        if (Connection is null)
            return null;
        SqlCommand cmd = new() {
            Connection = Connection,
            CommandType = CommandType.StoredProcedure
        };
        if (_adapterData.CacheDate is null)
            cmd.CommandText = "dbo.AdapterInsert";
        else
            cmd.CommandText = "dbo.CachedAdapterInsert";
        return cmd;
    }
    private SqlCommand? BuildAppCommand() {
        if (Connection is null)
            return null;
        try {
            SqlCommand cmd = new() {
                Connection = Connection,
                CommandType = CommandType.StoredProcedure,
                CommandText = "dbo.ApplicationInsert"
            };
            return cmd;
        } catch (Exception ex) {
            Logger.Append($"AppData: Failed to create parameters for ApplicationInsert. {ex.Message}");
        }
        return null;
    }
    private SqlCommand? BuildLoginCommand() {
        if (Connection is null)
            return null;
        SqlCommand cmd = new() {
            Connection = Connection,
            CommandType = CommandType.StoredProcedure
        };
        if (_loginData.CacheDate is null)
            cmd.CommandText = "dbo.LoginDataInsert";
        else
            cmd.CommandText = "dbo.CachedLoginDataInsert";
        return cmd;
    }
    private SqlCommand? BuildPrinterCommand() {
        if (Connection is null)
            return null;
        try {
            SqlCommand cmd = new() {
                Connection = Connection,
                CommandType = CommandType.StoredProcedure,
                CommandText = "dbo.PrinterInsert"
            };
            return cmd;
        } catch (Exception ex) {
            Logger.Append($"PrinterData: Failed to create parameters for PrinterInsert. {ex.Message}");
        }
        return null;
    }
    private SqlCommand? BuildStatCommand() {
        Logger.Append("StatLogging: Generating StatInsertObject");
        try {
            SqlCommand cmd = new() {
                Connection = Connection,
                CommandType = CommandType.StoredProcedure
            };
            if (_statData.CacheDate is null) {
                cmd.CommandText = "dbo.StatInsert";
            } else {
                cmd.CommandText = "dbo.CachedStatInsert";
            }
            return cmd;
        } catch (Exception ex) {
            Logger.Append($"StatData: Failed to create parameters for StatInsert {ex.Message}");
            return null;
        }
    }
    #endregion
    #region SQL Transmit Methods
    private bool AdapterDataToDb() => AdapterDataToDb(_adapterData);
    private bool AdapterDataToDb(AdapterCollection adapters) {
        Logger.Append($"AdapterData: Count: {_adapterData.Count}");
        SqlCommand? cmd = new();
        try {
            cmd = BuildAdapterCommand();
            if (cmd is null || Connection is null)
                return false;
            foreach (var adapter in adapters) {
                if (string.IsNullOrWhiteSpace(adapter.Description.Value))
                    continue;
                try {
                    cmd.Parameters.AddRange(adapter.GetSqlParameters());
                } catch (Exception ex) {
                    Logger.Append($"AdapterData: failed to assign parameters for AdapaterDataInsert. {ex.Message}");
                    adapter.ToCache = true;
                    return false;
                }
                if (Connection.State == ConnectionState.Closed) {
                    try {
                        Connection.Open();
                    } catch (Exception ex) {
                        Logger.Append($"AdapterData: failed to open connection. {ex.Message}");
                        adapter.ToCache = true;
                        return false;
                    }
                }
                try {
                    cmd.ExecuteNonQuery();
                    Logger.Append("AdapterData: AdapterDataInsert complete.");
                    return true;
                } catch (Exception ex) {
                    Logger.Append($"AdapterData: Failed to execute stored procedure AdapterInsert. {ex.Message}");
                    adapter.ToCache = true;
                    return false;
                }
            }
        } finally {
            cmd?.Dispose();
            Connection?.Close();
        }
        return true;
    }
    private void AppDataToDb() {
        SqlCommand? cmd = new();
        try {
            cmd = BuildAppCommand();
            if (cmd is null || Connection is null)
                return;
            try {
                cmd.Parameters.Add(_appData.GetSqlParameter());
            } catch (Exception ex) {
                Logger.Append($"AppData: failed to assign parameters for AppDataInsert. {ex.Message}");
            }
            if (Connection.State == ConnectionState.Closed) {
                try {
                    Connection.Open();
                } catch (Exception ex) {
                    Logger.Append($"AppData: failed to open connection. {ex.Message}");
                    return;
                }
            }
            try {
                cmd.ExecuteNonQuery();
                Logger.Append("AppData: AppDataInsert complete.");
                return;
            } catch (Exception ex) {
                Logger.Append($"AppData: Failed to execute stored procedure AppDataInsert. {ex.Message}");
                return;
            }
        } finally {
            cmd?.Dispose();
            Connection?.Close();
        }
    }
    private bool LoginDataToDb() => LoginDataToDb(_loginData);
    private bool LoginDataToDb(LoginData loginData) {
        SqlCommand? cmd = new();
        try {
        cmd = BuildLoginCommand();
        if (cmd is null || Connection is null)
            return false;
            try {
                cmd.Parameters.AddRange(loginData.GetSqlParameters());
            } catch (Exception ex) {
                Logger.Append($"LoginData: failed to assign parameters for LoginDataInsert. {ex.Message}");
                return false;
            }
            if (Connection.State == ConnectionState.Closed) {
                try {
                    Connection.Open();
                } catch (Exception ex) {
                    Logger.Append($"LoginData: failed to open connection. {ex.Message}");
                    return false;
                }
            }
            try {
                cmd.ExecuteNonQuery();
                Logger.Append("LoginData: LoginDataInsert complete.");
                return true;
            } catch (Exception ex) {
                Logger.Append($"LoginData: Failed to execute stored procedure LoginDataInsert. {ex.Message}");
                return false;
            }
        } finally {
            cmd?.Dispose();
            Connection?.Close();
        }
    }
    private void PrinterDataToDb() {
        SqlCommand? cmd = new();
        try {
            cmd = BuildPrinterCommand();
            if (cmd is null || Connection is null)
                return;
            try {
                cmd.Parameters.Add(_printerData.GetSqlParameter());
            } catch (Exception ex) {
                Logger.Append($"PrinterData: failed to assign parameters for PrinterDataInsert. {ex.Message}");
            }
            if (Connection.State == ConnectionState.Closed) {
                try {
                    Connection.Open();
                } catch (Exception ex) {
                    Logger.Append($"PrinterData: failed to open connection. {ex.Message}");
                    return;
                }
            }
            try {
                cmd.ExecuteNonQuery();
                Logger.Append("PrinterData: PrinterDataInsert complete.");
                return;
            } catch (Exception ex) {
                Logger.Append($"PrinterData: Failed to execute stored procedure PrinterDataInsert. {ex.Message}");
                return;
            }
        } finally {
            cmd?.Dispose();
            Connection?.Close();
        }
    }
    private bool StatDataToDb() => StatDataToDb(_statData);
    private bool StatDataToDb(StatData statData) {
        SqlCommand? cmd = new();
        try {
            cmd = BuildStatCommand();
            if (cmd is null || Connection is null)
                return false;
            try {
                cmd.Parameters.AddRange(statData.GetSqlParameters());
            } catch (Exception ex) {
                Logger.Append($"LoginData: failed to assign parameters for LoginDataInsert. {ex.Message}");
                return false;
            }
            if (Connection.State == ConnectionState.Closed) {
                try {
                    Connection.Open();
                } catch (Exception ex) {
                    Logger.Append($"LoginData: failed to open connection. {ex.Message}");
                    return false;
                }
            }
            try {
                cmd.ExecuteNonQuery();
                Logger.Append("LoginData: LoginDataInsert complete.");
                return true;
            } catch (Exception ex) {
                Logger.Append($"LoginData: Failed to execute stored procedure LoginDataInsert. {ex.Message}");
                return false;
            }
        } finally {
            cmd?.Dispose();
            Connection?.Close();
        }
    }
    #endregion
    #endregion
    #region File Write Methods
    private void AppDataToFile() {
        string destination = Path.Combine(_logPaths.AppLogs, $"{_computerName}.Applications.csv");
        StringBuilder sb = new();
        sb.AppendLine($"{_computerName},{Environment.UserName},APPLICATIONS");
        foreach (var app in _appData) {
            sb.Append(_computerName);
            sb.Append(",");
            sb.Append(Environment.UserName);
            sb.Append(",");
            if (app.ApplicationName.Value.Contains('"')) {
                sb.Append('"');
                sb.Append(app.ApplicationName.Value);
                sb.Append('"');
                sb.AppendLine();
            } else {
                sb.AppendLine(app.ApplicationName.Value);
            }
        }
        File.WriteAllText(destination, sb.ToString());
    }
    private void LoginDataToFile() {
        DateTime LogTime = DateTime.Now;
        string LogTime1 = LogTime.ToString("ddd MMM dd HH:mm:ss yyyy");
        string LogTime2 = LogTime.ToString($"ddd MMM dd HH:mm:ss {Utility.GetTimeZoneCode()} yyyy");
        string user = Environment.UserName;

        string MachineLogEntry = LogTime1 + " -- " + user + "\r\n";
        StringBuilder MachineStatEntry = new();
        foreach (DictionaryEntry env in Environment.GetEnvironmentVariables()) {
            MachineStatEntry.AppendLine($"{env.Key}={env.Value}");
        }
        ProcessStartInfo psi = new() {
            FileName = "ipconfig",
            Arguments = "/all",
            RedirectStandardOutput = true,
            UseShellExecute = true,
            CreateNoWindow = true
        };
        using Process process = new() { StartInfo = psi };
        process.Start();
        using var reader = process.StandardOutput;
        string? line;
        while ((line = reader.ReadLine()) is not null) {
            MachineStatEntry.AppendLine(line);
        }
        process.WaitForExit();
        string LogonEntry = string.Join("|", new string[] { user, _loginData.DC.Value ?? "", _computerName, LogTime2, _loginData.UserDN.Value ?? "" } );
        LogonEntry += "\r\n";


        string ThisMachineLog = _logPaths.MachineLogs + _computerName + ".log";
        string ThisMachineStats = _logPaths.MachineStats + _computerName + ".LOG";
        string ThisUserLogon = _logPaths.UserLogon + user + ".log";
        string ThisComputerLogon = _logPaths.ComputerLogon + _computerName + ".log";


        if (Directory.Exists(_logPaths.MachineLogs)) {
            File.AppendAllText(ThisMachineLog, MachineLogEntry);
        }
        if (Directory.Exists(_logPaths.MachineStats)) {
            File.AppendAllText(ThisMachineStats, MachineStatEntry.ToString());
        }
        if (Directory.Exists(_logPaths.UserLogon)) {
            File.AppendAllText(ThisUserLogon, LogonEntry);
        }
        if (Directory.Exists(_logPaths.ComputerLogon)) {
            File.AppendAllText(ThisComputerLogon, LogonEntry);
        }
    }
    private void PrinterDataToFile() {
        StringBuilder sb = new();
        sb.AppendLine("Computer, User, PORT, Network, Name, Location, Servername, ShareName, INAD, DriverName, Local_TCPIPPort");
        foreach (var printer in _printerData) {
            if (printer is null)
                continue;
            sb.AppendLine(printer.ToCsvRow());
        }
        File.WriteAllText(_logPaths.PrinterLogs, sb.ToString());
    }
    private void StatDataToFile() {
        StringBuilder inv = new();
        inv.AppendLine(DateTime.Now.ToString($"ddd MM/dd/yyy"));
        inv.AppendLine($"Computer Name: {_computerName}");
        inv.AppendLine($"Manufacturer: {_statData.Manufacturer.Value}");
        inv.AppendLine($"Model: {_statData.Model.Value}");
        inv.AppendLine($"IPAddress: {_loginData.IP.Value}");
        inv.AppendLine($"Operating System: {_statData.OSVersion}");
        inv.AppendLine($"Total Memory: {_statData.Memory.Value}");
        inv.AppendLine($"OS Install Date: {_statData.InstallDate.Value}");
        File.WriteAllText(_logPaths.StatLogs, inv.ToString());
    }
    #endregion
    #region Data Collection Methods
    private void CollectAppData() {
        string x64KeyPath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
        string x86KeyPath = @"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\";
        RegistryKey x64Key = Registry.LocalMachine.OpenSubKey(x64KeyPath);
        RegistryKey x86Key = Registry.LocalMachine.OpenSubKey(x86KeyPath);
        RegistryKey[] both = new[] { x64Key, x86Key };
        foreach (var archKey in both) {
            foreach (var key in archKey.GetSubKeyNames()) {
                string? displayName = archKey.OpenSubKey(key)?.GetValue("DisplayName")?.ToString();
                string? quietName = archKey.OpenSubKey(key)?.GetValue("QuietDisplayName")?.ToString();
                string? output;
                if (displayName is not null && quietName is not null)
                    output = $"{displayName}/{quietName}";
                else
                    output = displayName ?? quietName ?? null;
                if (output is not null)
                    _appData.Add(output);
            }
        }
    }
    private void CollectAdapterData() {
        foreach (var adapter in GetActiveNICData()) {
            string IP = adapter
                .GetIPProperties()
                .UnicastAddresses
                .Where(u => u.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                .Select(i => i.Address.ToString())
                .FirstOrDefault();
            string MAC = string
                .Join(
                    "-",
                    adapter
                        .GetPhysicalAddress()
                        .GetAddressBytes()
                        .Select(b => b.ToString("X2"))
                );
            _adapterData.Add( new AdapterData() {
                AdapterDesc = adapter.Description,
                AdapterState = adapter.OperationalStatus.ToString(),
                IPv4 = IP,
                MACVal = MAC
            });
            _loginData.IP.Value ??= IP;
            _loginData.MAC.Value ??= MAC;
        }
    }
    private void CollectLoginData() {
        if (_loginData.IP.Value is null)
            CollectAdapterData();
        _loginData.UserDN.Value = System.DirectoryServices.AccountManagement.UserPrincipal.Current.DistinguishedName;
        _loginData.UPN.Value = System.DirectoryServices.AccountManagement.UserPrincipal.Current.UserPrincipalName;
        _loginData.ODStatus.Value = ODStatus && GetOneDriveStatus();
        _loginData.Ex.Value = Exception;
        _loginData.Admin.Value = _loginData.UserDN.Value.Contains("OU=NPE");
    }
    private void CollectPrinterData() {
        using PrintServer printServer = new();
        var ports = GetTcpIpPrinterPorts();
        foreach (var pq in printServer.GetPrintQueues()) {
            PrinterData thisPrinter = new();
            thisPrinter.PrinterName.Value = pq.Name;
            thisPrinter.Port.Value = pq.QueuePort.Name;
            thisPrinter.Network.Value = pq.IsQueued;
            thisPrinter.Location.Value = pq.Location;
            thisPrinter.ServerName.Value = pq.HostingPrintServer?.Name;
            thisPrinter.ShareName.Value = pq.ShareName;
            thisPrinter.InAD.Value = pq.IsPublished;
            thisPrinter.DriverName.Value = pq.QueueDriver?.Name;
            if (!ports.TryGetValue(pq.QueuePort.Name, out thisPrinter.IPPort.Value)) {
                thisPrinter.IPPort.Value = null;
            }
            _printerData.Add(thisPrinter);
        }
    }
    private void CollectStatData() {
        const double gig = 1073741824;
        string registryPath = $@"System\CurrentControlSet\Control\{SiteCode}";
        RegistryKey? cache = Registry.CurrentUser.OpenSubKey(registryPath);
        if (cache is null) {
            Logger.Append("StatData: BIOS Data not cached. Generating registry cache.");
            cache = Registry.CurrentUser.CreateSubKey(registryPath);
            using var searcher = new ManagementObjectSearcher("SELECT SerialNumber FROM Win32_BIOS");
            _statData.SerialNumber.Value = searcher.Get().OfType<ManagementObject>().First()["SerialNumber"].ToString();
            if (cache is not null) {
                cache.SetValue("SN", _statData.SerialNumber.Value, RegistryValueKind.String);
                Logger.Append("HardwareInventory: BIOS data cached in registry. Skipping Win32_Bios");
            }
        } else {
            _statData.SerialNumber.Value = cache.GetValue("SN").ToString();
        }

        Logger.Append("HardwareInventory: Fetching CPU Count from Windows API");
        _statData.Cores.Value = HardwareStats
            .GetLogicalProcessorInformation()
            .Where(slpi => slpi.Relationship == HardwareStats.LOGICAL_PROCESSOR_RELATIONSHIP.RelationProcessorCore)
            .Count();
        Logger.Append("HardwareInventory: Fetching CPU data from Registry");
        _statData.CPUName.Value = Utility.GetRegValue(
                Registry.LocalMachine,
                @"HARDWARE\DESCRIPTION\System\CentralProcessor\0",
                "ProcessorNameString")?
            .ToString();
        _statData.Architecture.Value = Utility.GetRegValue(
                Registry.LocalMachine,
                @"System\CurrentControlSet\Control\Session Manager\Environment",
                "PROCESSOR_ARCHITECTURE")?
            .ToString();
        _statData.Manufacturer.Value = Utility.GetRegValue(
                Registry.LocalMachine,
                @"HARDWARE\DESCRIPTION\System\BIOS",
                "SystemManufacturer")?
            .ToString();
        _statData.Model.Value = Utility.GetRegValue(
                Registry.LocalMachine,
                @"HARDWARE\DESCRIPTION\System\BIOS",
                "SystemProductName")?
            .ToString();
        _statData.OSVersion.Value = Environment.OSVersion.Version.ToString();
        Logger.Append("HardwareInventory: Fetching RAM from Windows API");
        _statData.Memory.Value = (int)Math.Round(HardwareStats.GetTotalMem() / gig);
        Logger.Append("HardwareInventory: Fetching HDD data from Windows API");
        _statData.HDDSize.Value = 0;
        foreach (var drive in DriveInfo.GetDrives()) {
            if (drive.Name == @"C:\") {
                _statData.HDDSize.Value = (int)Math.Round(drive.TotalSize / gig);
                break;
            }
        }
        try {
            int regInstallDate = Int32
                .Parse(
                    Utility.GetRegValue(
                        Registry.LocalMachine,
                        @"\SOFTWARE\Microsoft\Windows NT\Current Version",
                        "InstallDate"
                    )!
                    .ToString()
                );
            _statData.InstallDate.Value = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc) + TimeSpan.FromSeconds(regInstallDate);
        } catch {
            try {
                using var searcher = new ManagementObjectSearcher("SELECT InstallDate FROM Win32_OperatingSystem");
                using var queryResult = searcher.Get();
                var os = queryResult.OfType<ManagementObject>().FirstOrDefault();

                if (os?["InstallDate"] is string installDateString) {
                    _statData.InstallDate.Value = DateTime.ParseExact(installDateString.Substring(0, 14), "yyyyMMddHHmmss", null);
                }
            } catch (Exception ex) {
                Logger.Append($"Failed to retrieve InstallDate: {ex.Message}");
            }
        }
        var uptime = new PerformanceCounter("System", "System Up Time");
        _ = uptime.NextValue();
        _statData.LastBoot.Value = DateTime.Now.Subtract(TimeSpan.FromSeconds(uptime.NextValue()));
        _statData.BTState.Value = true;
        try {
            var accessStatus = Radio.RequestAccessAsync().AsTask().GetAwaiter().GetResult();
            var radios = Radio.GetRadiosAsync().AsTask().GetAwaiter().GetResult();
            int btCount = radios
                .OfType<Radio>()
                .Where(r => r.Kind == RadioKind.Bluetooth && r.State == RadioState.On)
                .Count();
            Logger.Append($"HardwareInventory: Active BT Radios {btCount}");
            _statData.BTState.Value = btCount > 0;
        } catch {
            Logger.Append($"HardwareInventory: BT State indeterminate");
        }
        try {
            var tpmVer = HardwareStats.GetTPMVersion();
            _statData.TPMVersion.Value = $"{tpmVer.Major}.{tpmVer.Minor}";
        } catch {
            _statData.TPMVersion.Value = "Unk";
        }
        Logger.Append($"HardwareInventory: TPM Version Detected As: {_statData.TPMVersion.Value}");
    }
    private IEnumerable<NetworkInterface> GetActiveNICData() {
        var allowedNetworkInterfaceType = new[] {
            NetworkInterfaceType.Ethernet,
            NetworkInterfaceType.GigabitEthernet,
            NetworkInterfaceType.Wireless80211
        };
        return NetworkInterface
            .GetAllNetworkInterfaces()
            .Where(ni => allowedNetworkInterfaceType.Contains(ni.NetworkInterfaceType));
    }
    private bool GetOneDriveStatus() {
        const int AVAILABILITY_STATUS = 303;
        string oneDrivePath = 
            Environment.GetEnvironmentVariable("OneDriveCommercial") 
            ?? Environment.GetEnvironmentVariable("OneDrive");
        if (oneDrivePath is null)
            return false;
        string[] oneDrivePaths = {"Documents", "Desktop", "Pictures", "My Pictures"};
        bool oneActive = false;
        try {
            dynamic shell = Activator.CreateInstance(Type.GetTypeFromProgID("Shell.Application"));
            dynamic folder = shell.NameSpace(oneDrivePath);
            foreach (var path in oneDrivePaths) {
                try {
                    string thisPath = Path.Combine(oneDrivePath, path);
                    dynamic file = folder.ParseName(path);
                    string pathStatus = folder.getDetailsOf(file, AVAILABILITY_STATUS).ToLower();
                    oneActive |= pathStatus.Contains("available") || pathStatus.Contains("sync");
                } catch (Exception ex) {
                    Logger.Append($"Logging: Failed to get OneDrive status for {path}. {ex.Message}");
                }
            }
            Logger.Append($"Logging: OneDrive enabled: {oneActive}");
        } catch (Exception ex) {
            Logger.Append($"Logging: Failed to instantiate shell for OneDriveCheck. {ex.Message}");
        }
        
        return oneActive;
    }
    private static Dictionary<string, string> GetTcpIpPrinterPorts() {
        Dictionary<string, string> printerPorts = new();

        string registryPath = @"SYSTEM\CurrentControlSet\Control\Print\Monitors\Standard TCP/IP Port\Ports";
        using RegistryKey? portsKey = Registry.LocalMachine.OpenSubKey(registryPath);

        if (portsKey == null)
            return printerPorts;

        foreach (string portName in portsKey.GetSubKeyNames()) {
            using RegistryKey? portKey = portsKey.OpenSubKey(portName);
            if (portKey == null) continue;

            string? ipAddress = portKey.GetValue("IPAddress") as string;
            if (!string.IsNullOrEmpty(ipAddress)) {
                printerPorts[portName] = ipAddress!;
            }
        }

        return printerPorts;
    }
    #endregion
    #region Public Methods
    public void SetLoggingPaths(FileLoggingPaths paths) {
        _logPaths = paths;
        if (!string.IsNullOrWhiteSpace(paths.DebugLogs)) {
            Logger.LogFile = paths.DebugLogs;
        }
    }
    public void TransmitCacheData() {
        if (JsonCache is null) {
            return;
        }
        JsonCache = TransmitCacheData(JsonCache);
    }
    public string? TransmitCacheData(string cache) {
        CachedData? currentData = JsonSerializer.Deserialize<CachedData>(cache, JsonSettings.Options);
        if (currentData is null)
            return null;
        CachedData needsRetry = new();
        foreach (var entry in currentData) {
            AdapterCollection? retryAdapters = null;
            LoginData? retryLogin = null;
            StatData? retryStats = null;
            entry.UpdateCacheDates();
            if (entry.adapterCollection is not null)
                if (!AdapterDataToDb(entry.adapterCollection))
                    retryAdapters = entry.adapterCollection;
            if (entry.loginData is not null)
                if (!LoginDataToDb(entry.loginData))
                    retryLogin = entry.loginData;
            if (entry.statData is not null)
                if (!StatDataToDb(entry.statData))
                    retryStats = entry.statData;
            if (retryAdapters is not null || retryLogin is not null || retryStats is not null)
                needsRetry.Add(new CachedEntry(entry.CacheDate, retryLogin, retryAdapters, retryStats));
        }
        JsonCache = needsRetry.Count > 0 ? JsonSerializer.Serialize<CachedData>(needsRetry, JsonSettings.Options) : null;
        return JsonCache;
    }
    public bool TryGetCacheData(string? oldCache, bool attemptTransmit, out string? updatedCache) {
        if (string.IsNullOrWhiteSpace(oldCache) && !CacheNeeded) {
            updatedCache = null;
            return false;
        }
        CachedData cache = new();
        if (oldCache is not null) {
            cache = JsonSerializer.Deserialize<CachedData>(oldCache, JsonSettings.Options) ?? new();
        }
        if (CacheNeeded) {
            CachedEntry today = new(DateTime.Now, _loginData, _adapterData, _statData);
            cache.Add(today);
        }
        if (attemptTransmit && !CacheNeeded) {
            updatedCache = TransmitCacheData(oldCache!);
            return updatedCache is not null;
        }
        updatedCache = JsonSerializer.Serialize<CachedData>(cache, JsonSettings.Options);
        return true;
    }
    public void WriteAdapterData() {
        if (TsCheck())
            return;
        if (!LogToDB) {
            Logger.Append("WriteAdapterData: Logging skipped because LogToDB is disabled.");
            return;
        }
        try {
            CollectAdapterData();
        } catch {
            Logger.Append("WriteAdapterData: Collection of adapter data failed.");
            return;
        }
        if (!AdapterDataToDb()) {
            Logger.Append("WriteAdapterData: Transmission of adapter data failed. No further DB attempts will be made. Caching enabled.");
            LogToDB = false;
            LogToFile = true;
            _adapterData.CacheDate = DateTime.Now;
            _adapterData.UpdateCacheDates();
        }
    }
    public void WriteAppData() => WriteAppData(null);
    public void WriteAppData(string? Path) {
        if (TsCheck())
            return;
        if (Path is null)
            Path = _logPaths.AppLogs;
        bool appLogToFile = (Path is not null) && LogToFile;
        if (!LogToDB && !appLogToFile) {
            Logger.Append("WriteAppData: skipped because LogToDB and LogToFile are both off");
            return;
        }
        try {
            CollectAppData();
        } catch {
            Logger.Append("WriteAppData: Collection of application data failed.");
            return;
        }
        if (appLogToFile) {
            AppDataToFile();
        }
        if (LogToDB) {
            AppDataToDb();
        }
    }
    public void WriteLoginData() {
        if (TsCheck())
            return;

        bool loginToFile = LogToFile && (
            !string.IsNullOrWhiteSpace(_logPaths.MachineLogs) ||
            !string.IsNullOrWhiteSpace(_logPaths.MachineStats) ||
            !string.IsNullOrWhiteSpace(_logPaths.UserLogon) ||
            !string.IsNullOrWhiteSpace(_logPaths.ComputerLogon) 
        );
        bool loginToDb = Connection is not null && LogToDB;


        if (!loginToFile && !loginToDb) {
            Logger.Append("WriteLoginData: Logging skipped because LogToDB and LogToFile are both off");
            return;
        }
        Logger.Append("WriteLoginData: Logging not skipped by TS or logging options");

        try {
            CollectLoginData();
        } catch {
            Logger.Append("WriteLoginData: Collection of Login data failed.");
            return;
        }

        if (loginToFile) {
            LoginDataToFile();
        }
        if (loginToDb) {
            if (!LoginDataToDb()) {
                Logger.Append("WriteLoginData: Transmission of login data failed. No further DB attempts will be made. Caching enabled.");
                LogToDB = false;
                LogToFile = true;
                _loginData.CacheDate = DateTime.Now;
                _loginData.ToCache = true;
            }
        }
    }
    public void WritePrinterData() => WritePrinterData(null);
    public void WritePrinterData(string? Path) {
        if (TsCheck())
            return;
        if (Path is null)
            Path = _logPaths.PrinterLogs;
        bool printerLogToFile = (Path is not null) && LogToFile;
        if (!LogToDB && !printerLogToFile) {
            Logger.Append("WritePrinterData: skipped because LogToDB and LogToFile are both off");
            return;
        }
        try {
            CollectPrinterData();
        } catch {
            Logger.Append("WritePrinterData: Collection of printer data failed.");
            return;
        }
        if (printerLogToFile) {
            PrinterDataToFile();
        }
        if (LogToDB) {
            PrinterDataToDb();
        }
    }
    public void WriteStatData() => WriteStatData(null);
    public void WriteStatData(string? Path) {
        if (TsCheck())
            return;
        string registryPath = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion";
        string? osCaption = (string?)Utility.GetRegValue(Registry.LocalMachine, registryPath, "ProductName");
        if (osCaption is not null && osCaption.ToLower().Contains("server")) {
            Logger.Append("WriteStatData: Logging skipped due to Server rule");
            return;
        }
        if (Path is null)
            Path = _logPaths.StatLogs;
        bool loginToFile = LogToFile && !string.IsNullOrWhiteSpace(Path);
        bool loginToDb = Connection is not null && LogToDB;

        if (!loginToFile && !loginToDb) {
            Logger.Append("WriteStatData: Logging skipped because LogToDB and LogToFile are both off");
            return;
        }
        Logger.Append("WriteStatData: Logging not skipped by TS or logging options");

        try {
            CollectStatData();
        } catch {
            Logger.Append("WriteStatData: Collection of Stat data failed.");
            return;
        }

        if (loginToFile) {
            StatDataToFile();
        }
        if (loginToDb) {
            if (!StatDataToDb()) {
                Logger.Append("WriteStatData: Transmission of stat data failed. No further DB attempts will be made. Caching enabled.");
                LogToDB = false;
                LogToFile = true;
                _statData.CacheDate = DateTime.Now;
                _statData.ToCache = true;
            }
        }
    }
    #endregion


}   


 