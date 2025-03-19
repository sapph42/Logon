using System.Text.Json;
using System.Text.Json.Serialization;
using EudLogger.Classes.JsonConverters;

namespace EudLogger.Classes;

internal static class JsonSettings {
    public static readonly JsonSerializerOptions Options = new() {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = true,
        Converters = {
            new AdapterCollectionConverter(),
            new AdapterDataConverter(),
            new CachedEntryConverter(),
            new LoginDataConverter(),
            new StatDataConverter()
        }
    };
}
