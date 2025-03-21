using Microsoft.Win32;

namespace SapphTools.Logging.Classes;

internal static class Utility {
    public static object? GetRegValue(RegistryKey hive, string keyPath, string valueName) {
        return hive
            .OpenSubKey(keyPath)?
            .GetValue(valueName);
    }
    public static string GetTimeZoneCode() {
        TimeZoneInfo localZone = TimeZoneInfo.Local;
        bool isDaylight = localZone.IsDaylightSavingTime(DateTime.Now);
        return isDaylight ? localZone.DaylightName : localZone.StandardName;
    }
}
