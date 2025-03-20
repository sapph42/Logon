using System.Data.SqlClient;
using System.Diagnostics;
using Microsoft.SqlServer.Server;
using WebParam = System.Web.UI.WebControls.Parameter;

#nullable enable
namespace EudLogger.Classes;

internal class Parameter<T> {
    public string Name;
    public T? Value;
    public int? Size;
    public SqlDbType? DbType;
    public bool IsNull => Value is null;
    public string SqlName => $"@{Name}";
    public SqlMetaData SqlMetaData => new(Name, DbType!.Value, Size!.Value);
    public SqlParameter SqlParam => new(SqlName, DbType) { Value = Value ?? (object)DBNull.Value };
    public Parameter(string name, SqlDbType dbType) {
        Name = name;
        DbType = dbType;
    }
    public Parameter(string name, T? value) {
        Name = name;
        Value = value;
        DbType = BestFit(value);
    }
    public Parameter(string name, SqlDbType dbType, int size) {
        Name = name;
        DbType = dbType;
        Size = size;
    }
    private static SqlDbType BestFit(object? value) {
        if (value is null)
            return SqlDbType.NVarChar; //Default value of SqlParamter.DbType
        Type valType = value.GetType();
        var dbType = WebParam.ConvertTypeCodeToDbType(Type.GetTypeCode(value.GetType()));
        SqlParameter nonce = new();
        try {
            nonce.DbType = dbType;
        } catch (Exception ex) {
            Debug.WriteLine($"Failed to convert {valType.Name} from {dbType} to SqlDbType. {ex.Message}");
            return SqlDbType.NVarChar; //Default value of SqlParamter.DbType
        }
        return (SqlDbType)nonce.SqlDbType;
    }
}
