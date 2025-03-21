using System.Text.Json;

#nullable enable
namespace SapphTools.Logging.Classes.JsonConverters;
internal class AdapterDataConverter : JsonConverter<AdapterData> {
    public override AdapterData? Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options) {
        if (reader.TokenType != JsonTokenType.StartObject)
            throw new JsonException("Expected StartObject token.");
        var adapterData = new AdapterData();
        using JsonDocument doc = JsonDocument.ParseValue(ref reader);
        foreach (var property in doc.RootElement.EnumerateObject()) {
            switch (property.Name) {
                case "AdapterDesc":
                    adapterData.Description.Value = property.Value.GetString();
                    break;
                case "AdapterState":
                    adapterData.State.Value = property.Value.GetString();
                    break;
                case "IPv4":
                    adapterData.IP.Value = property.Value.GetString();
                    break;
                case "MAC":
                    adapterData.MAC.Value = property.Value.GetString();
                    break;
            }
        }
        return adapterData;
    }

    public override void Write(Utf8JsonWriter writer, AdapterData value, JsonSerializerOptions options) {
        writer.WriteStartObject();
        writer.WriteString("AdapterDesc", value.Description.Value);
        writer.WriteString("AdapterState", value.State.Value);
        writer.WriteString("IPv4", value.IP.Value);
        writer.WriteString("MAC", value.MAC.Value);
        writer.WriteEndObject();
    }
}
