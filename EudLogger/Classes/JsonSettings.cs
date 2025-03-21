using System.Text.Json;
using SapphTools.Logging.Classes.JsonConverters;

namespace SapphTools.Logging.Classes;

internal static class JsonSettings {
    public static readonly JsonSerializerOptions Options = new() {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = true,
        Converters = {
            new AdapterCollectionConverter(),
            new AdapterDataConverter(),
            new CachedDataConverter(),
            new CachedEntryConverter(),
            new LoginDataConverter(),
            new StatDataConverter()
        }
    };
}
