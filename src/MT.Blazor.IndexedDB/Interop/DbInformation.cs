
namespace MT.Blazor.IndexedDB.Interop;

internal class DbInformation
{
    public int Version { get; set; }
        
    public StoreSchema[] Stores { get; set; }
}