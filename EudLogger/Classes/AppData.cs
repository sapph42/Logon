namespace EudLogger.Classes;

internal class AppData : Data {
    public Parameter<string> ApplicationName = new("ApplicationName", SqlDbType.VarChar);
    public AppData() { }
    public AppData(string applicationName) {
        ApplicationName.Value = applicationName.Trim();
    }
}
