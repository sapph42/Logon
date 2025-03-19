namespace EudLogger.Classes;

#nullable enable
internal class LoginData : Data {
    public DateTime?         CacheDate = null;
    public Parameter<string> UserDN    = new("UserDN", SqlDbType.NVarChar);
    public Parameter<string> UPN       = new("UPN", SqlDbType.Char);
    public Parameter<string> IP        = new("IP", SqlDbType.VarChar);
    public Parameter<string> MAC       = new("MAC", SqlDbType.Char);
    public Parameter<string> DC        = new("DC", SqlDbType.VarChar);
    public Parameter<bool>   ODStatus  = new("ODStatus", SqlDbType.Bit);
    public Parameter<int>    ODCount   = new("ODCount", SqlDbType.Int);
    public Parameter<string> Ex        = new("Exception", SqlDbType.VarChar);
    public Parameter<bool>   Admin     = new("SAAccount", SqlDbType.Bit);
    public LoginData() { }

}
