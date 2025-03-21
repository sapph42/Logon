using System.Text.Json;

namespace SapphTools.Logging.Classes.JsonConverters;

internal class CachedDataConverter : JsonConverter<CachedData> {
    public override CachedData Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options) {
        if (reader.TokenType != JsonTokenType.StartObject) {
            throw new JsonException("Expected start of JSON object.");
        }

        CachedData cachedData = new();

        while (reader.Read()) {
            if (reader.TokenType == JsonTokenType.EndObject) {
                return cachedData;
            }

            if (reader.TokenType == JsonTokenType.PropertyName && reader.GetString() == "CachedData") {
                reader.Read();
                cachedData = JsonSerializer.Deserialize<CachedData>(ref reader, options) ?? new CachedData();
            } else {
                reader.Skip(); // Skip unknown properties
            }
        }

        throw new JsonException("Unexpected end of JSON while parsing CachedData.");
    }

    public override void Write(Utf8JsonWriter writer, CachedData value, JsonSerializerOptions options) {
        writer.WriteStartObject();
        writer.WritePropertyName("CachedData");
        JsonSerializer.Serialize(writer, (List<CachedEntry>)value, options);
        writer.WriteEndObject();
    }
}
