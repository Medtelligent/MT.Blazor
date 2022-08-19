using System.Collections.Generic;

namespace MT.Blazor.IndexedDB.Interop;

public class DbSchema
{
    public string Name { get; set; }
        
    public int Version { get; set; }
        
    public List<StoreSchema> Stores { get; } = new();
}