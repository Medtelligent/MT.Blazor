using System;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.JSInterop;

namespace MT.Blazor.IndexedDB.Interop;

internal class IndexedDbConnector : IIndexedDbConnector
{
    private readonly Lazy<Task<IJSObjectReference>> _jsModuleTask;
    private IJSObjectReference _jsModule;

    public IndexedDbConnector(IJSRuntime jsRuntime)
    {
        _jsModuleTask = new Lazy<Task<IJSObjectReference>>(() => jsRuntime.InvokeAsync<IJSObjectReference>("import", "./_content/MT.Blazor.IndexedDB/indexedDbInterop.js").AsTask());
    }

    public async Task<IJSObjectReference> OpenDb(DbSchema schema)
    {
        await EnsureJsModule();

        var currentSchema = await _jsModule.InvokeAsync<DbInformation>(DbFunctions.DbInfo, schema.Name);
        SetSchemaVersion(currentSchema, schema);
            
        return await _jsModule.InvokeAsync<IJSObjectReference>(DbFunctions.OpenDb, schema);
    }

    public async Task CloseDb(string dbName)
    {
        if (string.IsNullOrEmpty(dbName))
        {
            throw new ArgumentException("dbName cannot be null or empty", nameof(dbName));
        }
            
        await EnsureJsModule();
            
        await _jsModule.InvokeVoidAsync(DbFunctions.CloseDb, dbName);
    }

    public async Task DeleteDb(string dbName)
    {
        if (string.IsNullOrEmpty(dbName))
        {
            throw new ArgumentException("dbName cannot be null or empty", nameof(dbName));
        }
            
        await EnsureJsModule();
            
        await _jsModule.InvokeVoidAsync(DbFunctions.DeleteDb, dbName);
    }

    public async ValueTask DisposeAsync()
    {
        if (_jsModuleTask.IsValueCreated)
        {
            var module = await _jsModuleTask.Value;

            await module.InvokeVoidAsync(DbFunctions.Dispose);
            await module.DisposeAsync();
        }
    }

    private async Task EnsureJsModule()
    {
        if (_jsModule is not null)
        {
            return;
        }
            
        var moduleFactory = await _jsModuleTask.Value;
        _jsModule = await moduleFactory.InvokeAsync<IJSObjectReference>("createManager");
    }

    private static void SetSchemaVersion(DbInformation currentSchema, DbSchema newSchema)
    {
        if (!currentSchema.Stores.Any())
        {
            newSchema.Version = 1;
            return;
        }
            
        // change in stores
        var currentStoreNames = currentSchema.Stores.Select(s => s.Name).ToArray();
        var newStoreNames = newSchema.Stores.Select(s => s.Name).ToArray();
            
        if (currentStoreNames.Union(newStoreNames).Except(currentStoreNames.Intersect(newStoreNames)).Any())
        {
            newSchema.Version = currentSchema.Version + 1;
            return;
        }
            
        // change in indexes
        var newSchemaStoreLookup = newSchema.Stores.ToDictionary(s => s.Name);
            
        foreach (var currentStore in currentSchema.Stores)
        {
            var newStore = newSchemaStoreLookup[currentStore.Name];
                
            // store type
            if (currentStore.IsKeyVal != newStore.IsKeyVal)
            {
                newSchema.Version = currentSchema.Version + 1;
                return;
            }

            // primary key
            if (!currentStore.IsKeyVal && currentStore.PrimaryKey?.KeyPath != newStore.PrimaryKey?.KeyPath)
            {
                newSchema.Version = currentSchema.Version + 1;
                return;
            }
                
            // indexes
            var currentIndexNames = currentStore.Indexes.Select(i => i.Name).ToArray();
            var newIndexNames = newStore.Indexes.Select(i => i.Name).ToArray();

            if (!currentIndexNames.Union(newIndexNames).Except(currentIndexNames.Intersect(newIndexNames)).Any())
            {
                continue;
            }
                
            newSchema.Version = currentSchema.Version + 1;
            return;
        }
    }
}