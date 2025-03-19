using System.Text.Json.Serialization;

namespace EudLogger.Classes;

#nullable enable
internal class AdapterData : Data {
    public DateTime?         CacheDate   = null;

    public Parameter<string> Description = new("AdapterDesc",  SqlDbType.VarChar);
    public Parameter<string> State       = new("AdapterState", SqlDbType.VarChar);
    public Parameter<string> IP          = new("IPv4",         SqlDbType.VarChar);
    public Parameter<string> MAC         = new("MAC",          SqlDbType.VarChar);

    [JsonInclude]
    [JsonPropertyName("Description")]
    internal string AdapterDesc {
        get => Description.Value!;
        set => Description.Value = value;
    }
    [JsonInclude]
    [JsonPropertyName("State")]
    internal string AdapterState {
        get => State.Value!;
        set => State.Value = value;
    }
    [JsonInclude]
    [JsonPropertyName("IP")]
    internal string IPv4 {
        get => IP.Value ?? "";
        set => IP.Value = value;
    }
    [JsonInclude]
    [JsonPropertyName("MAC")]
    internal string MACVal {
        get => MAC.Value!;
        set => MAC.Value = value;
    }
    public AdapterData() { }
}
