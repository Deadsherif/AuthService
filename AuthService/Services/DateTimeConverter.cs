using System;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace AuthService.Services
{
    public class DateTimeConverter : JsonConverter<DateTime>
    {
        public override DateTime Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
        {
            string dateString = reader.GetString();
            if (string.IsNullOrEmpty(dateString))
                return DateTime.MinValue;

            // Try parsing ISO 8601 format with timezone
            if (DateTime.TryParse(dateString, null, System.Globalization.DateTimeStyles.RoundtripKind, out DateTime result))
            {
                return result;
            }
            
            // Try parsing without RoundtripKind for formats like "yyyy-MM-dd HH:mm:ss"
            if (DateTime.TryParse(dateString, null, System.Globalization.DateTimeStyles.None, out DateTime result2))
            {
                return result2;
            }
            
            return DateTime.MinValue;
        }

        public override void Write(Utf8JsonWriter writer, DateTime value, JsonSerializerOptions options)
        {
            writer.WriteStringValue(value.ToString("yyyy-MM-ddTHH:mm:ss.ffffffZ"));
        }
    }
}
