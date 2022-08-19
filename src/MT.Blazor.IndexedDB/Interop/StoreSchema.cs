using System.Collections.Generic;

namespace MT.Blazor.IndexedDB.Interop;

public class StoreSchema
{ 
    public int? DbVersion { get; set; }
        
    public string Name { get; set; }
        
    public bool IsKeyVal { get; set; }
        
    public IndexSpec PrimaryKey { get; set; }

    public List<IndexSpec> Indexes { get; set; } = new();
}