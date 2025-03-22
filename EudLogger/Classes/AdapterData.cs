namespace SapphTools.Logging.Classes;

#nullable enable
internal class AdapterData : Data {
    public DateTime?         CacheDate   = null;

    public Parameter<string> Description = new("AdapterDesc",  SqlDbType.VarChar);
    public Parameter<string> State       = new("AdapterState", SqlDbType.VarChar);
    public Parameter<string> IP          = new("IPv4",         SqlDbType.VarChar);
    public Parameter<string> MAC         = new("MAC",          SqlDbType.VarChar);

    internal string AdapterDesc {
        get => Description.Value!;
        set => Description.Value = value;
    }
    internal string AdapterState {
        get => State.Value!;
        set => State.Value = value;
    }
    internal string IPv4 {
        get => IP.Value ?? "";
        set => IP.Value = value;
    }
    internal string MACVal {
        get => MAC.Value!;
        set => MAC.Value = value;
    }
    public AdapterData() { }
}
