using System.Reflection;
using System.Data.SqlClient;
using Microsoft.SqlServer.Server;
using System.Text;

#nullable enable
namespace EudLogger.Classes;
internal abstract class Data {
    public bool ToCache { get; set; } = false;
    public SqlMetaData[] GetSqlMetaData() {
        return GetType()
            .GetFields(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance)
            .Where(f => f.FieldType.IsGenericType && f.FieldType.GetGenericTypeDefinition() == typeof(Parameter<>))
            .Select(f => f.GetValue(this) as dynamic)
            .Where(param => param is not null)
            .Select(param => param.GetSqlMetaData())
            .Cast<SqlMetaData>()
            .ToArray();
    }
    public SqlParameter[] GetSqlParameters() {
        return GetType()
            .GetFields(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance)
            .Where(f => f.FieldType.IsGenericType && f.FieldType.GetGenericTypeDefinition() == typeof(Parameter<>))
            .Select(f => f.GetValue(this) as dynamic)
            .Where(param => param is not null)
            .Where(param => param.Name != "CacheDate" || param.Value is not null)
            .Select(param => param.SqlParam)
            .Cast<SqlParameter>()
            .ToArray();
    }
    public string ToCsvRow(params string[] staticFields) {
        var fields = GetType()
            .GetFields(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance)
            .Where(f => f.FieldType.IsGenericType && f.FieldType.GetGenericTypeDefinition() == typeof(Parameter<>));

        StringBuilder sb = new();
        foreach (string staticField in staticFields) {
            sb.Append(staticField);
            sb.Append(",");
        }
        foreach (var field in fields) {
            dynamic? param = field.GetValue(this);
            if (param is null) {
                sb.Append(",");
                continue;
            }

            string? value = param.Value?.ToString(); // Convert value to string
            if (string.IsNullOrEmpty(value)) {
                sb.Append(",");
            } else {
                // Escape quotes and wrap in double quotes if needed
                value = value!.Contains(",") || value.Contains("\"") || value.Contains("\n") || value.Contains("\r")
                    ? $"\"{value.Replace("\"", "\"\"")}\""
                    : value;
                sb.Append(value + ",");
            }
        }

        if (sb.Length > 0)
            sb.Length--; // Remove trailing comma

        return sb.ToString();
    }
}
