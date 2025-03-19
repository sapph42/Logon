using System.Text.Json;

#nullable enable
namespace EudLogger.Classes.JsonConverters;
internal class CachedEntryConverter : JsonConverter<CachedEntry> {
    public override CachedEntry? Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options) {
        if (reader.TokenType != JsonTokenType.StartObject)
            throw new JsonException("Expected StartObject token");

        LoginData? loginData = new();
        AdapterCollection? adapterCollection = new();
        StatData? statData = new();
        DateTime cacheDate = new();
        using JsonDocument doc = JsonDocument.ParseValue(ref reader);
        foreach (var property in doc.RootElement.EnumerateObject()) {
            switch (property.Name) {
                case "Date":
                    cacheDate = property.Value.GetDateTime();
                    break;
                case "LoginData":
                    loginData = property.Value.Deserialize<LoginData>(options);
                    break;
                case "Adapters":
                    adapterCollection = property.Value.Deserialize<AdapterCollection>(options);
                    break;
                case "SystemStats":
                    statData = property.Value.Deserialize<StatData>(options);
                    break;
            }
        }
        if (loginData is null && adapterCollection is null && statData is null)
            return null;
        return new CachedEntry(cacheDate, loginData, adapterCollection, statData);
    }

    public override void Write(Utf8JsonWriter writer, CachedEntry value, JsonSerializerOptions options) {
        writer.WriteStartObject();
        writer.WriteString("Date", value.CacheDate);
        writer.WritePropertyName("LoginData");
        JsonSerializer.Serialize(writer, value.loginData, options);
        writer.WritePropertyName("Adapters");
        JsonSerializer.Serialize(writer, value.adapterCollection, options);
        writer.WritePropertyName("SystemStats");
        JsonSerializer.Serialize(writer, value.statData, options);
        writer.WriteEndObject();
    }
}
