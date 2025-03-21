#nullable enable
namespace SapphTools.Logging.Classes;

internal class PrinterData : Data {
    public Parameter<string> PrinterName = new("printername", SqlDbType.VarChar, 50);
    public Parameter<string?> Port = new("port", SqlDbType.VarChar, 75);
    public Parameter<bool> Network = new("network", SqlDbType.Bit);
    public Parameter<string?> Location = new("location", SqlDbType.VarChar, 100);
    public Parameter<string?> ServerName = new("servername", SqlDbType.VarChar, 25);
    public Parameter<string?> ShareName = new("sharename", SqlDbType.VarChar, 50);
    public Parameter<bool> InAD = new("InAD", SqlDbType.Bit);
    public Parameter<string?> DriverName = new("drivername", SqlDbType.VarChar, 100);
    public Parameter<string?> IPPort = new("Local_TCPIPPort", SqlDbType.VarChar, 50);
}
