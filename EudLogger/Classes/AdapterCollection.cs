﻿namespace SapphTools.Logging.Classes;

#nullable enable
internal class AdapterCollection : List<AdapterData> {
    public DateTime? CacheDate = null;
    public bool ToCache => this.Any(ad => ad.ToCache);
    public void UpdateCacheDates() {
        foreach (var adapter in this) {
            adapter.CacheDate = CacheDate;
        }
    }
}
