using Microsoft.SqlServer.Server;
using System.Data.SqlClient;

namespace EudLogger.Classes;

internal class AppCollection : List<AppData> {
    internal SqlMetaData TableType = new("applicationname", SqlDbType.VarChar, -1);
    public void Add(string applicationName) {
        var data = new AppData();
        data.ApplicationName.Value = applicationName.Trim();
        Add(data);
    }
    public SqlParameter GetSqlParameter() {
        return new SqlParameter() {
            ParameterName = "@ApplicationList",
            SqlDbType = SqlDbType.Structured,
            Direction = ParameterDirection.Input,
            TypeName = "dbo.ApplicationList",
            Value = GetApplicationData()
        };
    }
    private List<SqlDataRecord> GetApplicationData() {
        List<SqlDataRecord> appList = new();
        var uniqueApps = this
            .Where(app => app.ApplicationName.Value is not null)
            .Select(app => app.ApplicationName.Value)
            .Distinct();
        foreach (var app in uniqueApps) {
            SqlDataRecord record = new(TableType);
            record.SetString(record.GetOrdinal("applicationname"), app);
            appList.Add(record);
        }
        return appList;
    }
}
