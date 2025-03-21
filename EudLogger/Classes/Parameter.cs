using System.Data.SqlClient;
using System.Diagnostics;
using Microsoft.SqlServer.Server;
using WebParam = System.Web.UI.WebControls.Parameter;

#nullable enable
namespace SapphTools.Logging.Classes;

internal class Parameter<T> {
    public string Name;
    public T? Value;
    public long? Size;
    public SqlDbType? DbType;
    public bool IsNull => Value is null;
    public string SqlName => $"@{Name}";
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
    public SqlMetaData GetSqlMetaData() {
        SqlDbType type = DbType ?? BestFit(Value);
        switch (type) {
            case SqlDbType.Binary:
            case SqlDbType.Image:
            case SqlDbType.VarBinary:
                return new SqlMetaData(Name, type, Size ?? SqlMetaData.Max);
            case SqlDbType.Char:
            case SqlDbType.NChar:
            case SqlDbType.NText:
            case SqlDbType.NVarChar:
            case SqlDbType.Text:
            case SqlDbType.VarChar:
                return new SqlMetaData(Name, type, Size ?? (long?)Value?.ToString()?.Length ?? -1);
            default:
                return new SqlMetaData(Name, type);
        }
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
