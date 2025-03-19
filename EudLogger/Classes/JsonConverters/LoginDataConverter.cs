using System.Text.Json;

#nullable enable
namespace EudLogger.Classes.JsonConverters;
internal class LoginDataConverter : JsonConverter<LoginData> {
    public override LoginData? Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options) {
        if (reader.TokenType != JsonTokenType.StartObject)
            throw new JsonException("Expected StartObject token");

        var loginData = new LoginData();
        using JsonDocument doc = JsonDocument.ParseValue(ref reader);
        foreach (var property in doc.RootElement.EnumerateObject()) {
            switch (property.Name) {
                case "UserDN":
                    loginData.UserDN.Value = property.Value.GetString();
                    break;
                case "UPN":
                    loginData.UPN.Value = property.Value.GetString();
                    break;
                case "IP":
                    loginData.IP.Value = property.Value.GetString();
                    break;
                case "MAC":
                    loginData.MAC.Value = property.Value.GetString();
                    break;
                case "DC":
                    loginData.DC.Value = property.Value.GetString();
                    break;
                case "ODStatus":
                    loginData.ODStatus.Value = property.Value.GetBoolean();
                    break;
                case "ODCount":
                    loginData.ODCount.Value = property.Value.GetInt32();
                    break;
                case "Exception":
                    loginData.Ex.Value = property.Value.GetString();
                    break;
                case "SAAccount":
                    loginData.Admin.Value = property.Value.GetBoolean();
                    break;
            }
        }
        return loginData;
    }

    public override void Write(Utf8JsonWriter writer, LoginData value, JsonSerializerOptions options) {
        writer.WriteStartObject();
        writer.WriteString("UserDN", value.UserDN.Value);
        writer.WriteString("UPN", value.UPN.Value);
        writer.WriteString("IP", value.IP.Value);
        writer.WriteString("MAC", value.MAC.Value);
        writer.WriteString("DC", value.DC.Value);
        writer.WriteBoolean("ODStatus", value.ODStatus.Value);
        writer.WriteNumber("ODCount", value.ODCount.Value);
        writer.WriteString("Exception", value.Ex.Value);
        writer.WriteBoolean("SAAcount", value.Admin.Value);
        writer.WriteEndObject();
    }
}
