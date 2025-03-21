using System.Text.Json;

#nullable enable
namespace SapphTools.Logging.Classes.JsonConverters;
internal class StatDataConverter : JsonConverter<StatData> {
    public override StatData? Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options) {
        if (reader.TokenType != JsonTokenType.StartObject)
            throw new JsonException("Expected StartObject token");

        var statData = new StatData();
        using JsonDocument doc = JsonDocument.ParseValue(ref reader);
        foreach (var property in doc.RootElement.EnumerateObject()) {
            switch (property.Name) {
                case "Cores":
                    statData.Cores.Value = property.Value.GetInt32();
                    break;
                case "Arch":
                    statData.Architecture.Value = property.Value.GetString();
                    break;
                case "Id":
                    statData.CPUName.Value = property.Value.GetString();
                    break;
                case "Manuf":
                    statData.Manufacturer.Value = property.Value.GetString();
                    break;
                case "Model":
                    statData.Model.Value = property.Value.GetString();
                    break;
                case "SN":
                    statData.SerialNumber.Value = property.Value.GetString();
                    break;
                case "OSVer":
                    statData.OSVersion.Value = property.Value.GetString();
                    break;
                case "Mem":
                    statData.Memory.Value = property.Value.GetInt32();
                    break;
                case "HDD":
                    statData.HDDSize.Value = property.Value.GetInt32();
                    break;
                case "InstallDate":
                    statData.InstallDate.Value = property.Value.GetDateTime();
                    break;
                case "LastBoot":
                    statData.LastBoot.Value = property.Value.GetDateTime();
                    break;
                case "BTState":
                    statData.BTState.Value = property.Value.GetBoolean();
                    break;
                case "TPMVersion":
                    statData.TPMVersion.Value = property.Value.GetString();
                    break;
            }
        }
        return statData;
    }

    public override void Write(Utf8JsonWriter writer, StatData value, JsonSerializerOptions options) {
        writer.WriteStartObject();
        writer.WriteNumber("Cores", value.Cores.Value);
        writer.WriteString("Arch", value.Architecture.Value);
        writer.WriteString("Id", value.CPUName.Value);
        writer.WriteString("Manuf", value.Manufacturer.Value);
        writer.WriteString("Model", value.Model.Value);
        writer.WriteString("SN", value.SerialNumber.Value);
        writer.WriteString("OSVer", value.OSVersion.Value);
        writer.WriteNumber("Mem", value.Memory.Value);
        writer.WriteNumber("HDD", value.HDDSize.Value);
        writer.WriteString("InstallDate", value.InstallDate.Value);
        writer.WriteString("LastBoot", value.LastBoot.Value);
        writer.WriteBoolean("BTState", value.BTState.Value);
        writer.WriteString("TPMVersion", value.TPMVersion.Value);
        writer.WriteEndObject();
    }
}