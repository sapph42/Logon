#nullable enable
namespace EudLogger.Classes;
internal class CachedEntry {
    public DateTime CacheDate;
    public LoginData? loginData;
    public AdapterCollection? adapterCollection;
    public StatData? statData;

    [JsonConstructor]
    public CachedEntry(DateTime cacheDate, LoginData? login, AdapterCollection? adapters, StatData? stats) {
        CacheDate = cacheDate;
        loginData = login;
        adapterCollection = adapters;
        statData = stats;
    }
    public void UpdateCacheDates() {
        if (loginData is not null) 
            loginData.CacheDate = CacheDate;
        if (adapterCollection is not null) {
            adapterCollection.CacheDate = CacheDate;
            adapterCollection.UpdateCacheDates();
        }
        if (statData is not null)
            statData.CacheDate = CacheDate;
    }
}

