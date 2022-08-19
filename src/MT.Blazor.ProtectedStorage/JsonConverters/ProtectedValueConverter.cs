using System;
using System.Text.Json;
using System.Text.Json.Serialization;
using MT.Blazor.ProtectedStorage.Extensions;

namespace MT.Blazor.ProtectedStorage.JsonConverters;

public class ProtectedValueConverter : JsonConverter<ProtectedValue>
{
    public override ProtectedValue Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        var value = reader.GetString().NullIfEmpty();

        return value == null 
            ? null 
            : new ProtectedValue(value);
    }

    public override void Write(Utf8JsonWriter writer, ProtectedValue value, JsonSerializerOptions options)
    {
        writer.WriteStringValue(value.ToString());
    }
}