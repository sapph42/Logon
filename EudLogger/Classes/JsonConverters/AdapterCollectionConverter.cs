using System.Text.Json;

namespace EudLogger.Classes.JsonConverters;
internal class AdapterCollectionConverter : JsonConverter<AdapterCollection> {
    public override AdapterCollection Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options) {
        var adapters = JsonSerializer.Deserialize<List<AdapterData>>(ref reader, options);
        if (adapters is null)
            return new AdapterCollection();
        var collection = new AdapterCollection { Capacity = adapters.Count };
        collection.AddRange(adapters.Where(a => a is not null));
        return collection;
    }

    public override void Write(Utf8JsonWriter writer, AdapterCollection value, JsonSerializerOptions options) {
        JsonSerializer.Serialize(writer, (List<AdapterData>)value.Where(v => v is not null), options);
    }
}
