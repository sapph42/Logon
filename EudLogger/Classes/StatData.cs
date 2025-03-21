namespace SapphTools.Logging.Classes;

#nullable enable
internal class StatData : Data {
    public DateTime?           CacheDate    = null;

    public Parameter<int>      Cores        = new("Cores",       SqlDbType.Int);
    public Parameter<string>   Architecture = new("Arch",        SqlDbType.VarChar);
    public Parameter<string>   CPUName      = new("Id",          SqlDbType.VarChar);
    public Parameter<string>   Manufacturer = new("Manuf",       SqlDbType.VarChar);
    public Parameter<string>   Model        = new("Model",       SqlDbType.VarChar);
    public Parameter<string>   SerialNumber = new("SN",          SqlDbType.VarChar);
    public Parameter<string>   OSVersion    = new("OSVer",       SqlDbType.VarChar);
    public Parameter<int>      Memory       = new("Mem",         SqlDbType.Int);
    public Parameter<int>      HDDSize      = new("HDD",         SqlDbType.Int);
    public Parameter<DateTime> InstallDate  = new("InstallDate", SqlDbType.DateTime2);
    public Parameter<DateTime> LastBoot     = new("LastBoot",    SqlDbType.DateTime2);
    public Parameter<bool>     BTState      = new("BTState",     SqlDbType.Bit);
    public Parameter<string>   TPMVersion   = new("TPMVersion",  SqlDbType.VarChar);

    public StatData() { }
}