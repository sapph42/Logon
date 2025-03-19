using Microsoft.SqlServer.Server;
using System.Data.SqlClient;
using System.Reflection;

#nullable enable
namespace EudLogger.Classes;
internal class PrinterCollection : List<PrinterData> {

    internal SqlMetaData[] TableType => this.FirstOrDefault().GetSqlMetaData();
    public SqlParameter GetSqlParameter() {
        return new SqlParameter() {
            ParameterName = "@PrinterList",
            SqlDbType = SqlDbType.Structured,
            Direction = ParameterDirection.Input,
            TypeName = "dbo.PrinterList",
            Value = GetPrinterData()
        };
    }
    private List<SqlDataRecord> GetPrinterData() {
        List<SqlDataRecord> printerList = new();
        var properties = typeof(PrinterData)
            .GetFields(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance)
            .Where(f => f.FieldType.IsGenericType && f.FieldType.GetGenericTypeDefinition() == typeof(Parameter<>));

        foreach (var printer in this) {
            SqlDataRecord record = new(TableType);

            foreach (var property in properties) {
                dynamic? propertyInstance = property.GetValue(printer);
                if (propertyInstance is null) continue; // Skip if the property itself is null

                string propertyName = propertyInstance.Name;
                object? value = propertyInstance.Value;

                int ordinal = record.GetOrdinal(propertyName);

                switch (value) {
                    case string strValue:
                        record.SetString(ordinal, strValue);
                        break;
                    case bool boolValue:
                        record.SetBoolean(ordinal, boolValue);
                        break;
                    case null:
                        record.SetDBNull(ordinal);
                        break;
                    default:
                        throw new InvalidOperationException($"Unsupported type: {value.GetType()}");
                }
            }
            printerList.Add(record);
        }
        return printerList;
    }
}
