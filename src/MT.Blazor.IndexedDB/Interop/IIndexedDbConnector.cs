using System;
using System.Threading.Tasks;
using Microsoft.JSInterop;

namespace MT.Blazor.IndexedDB.Interop;

public interface IIndexedDbConnector : IAsyncDisposable
{
    Task<IJSObjectReference> OpenDb(DbSchema schema);
        
    Task CloseDb(string dbName);
    
    Task DeleteDb(string dbName);
}