using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using MT.Blazor.IndexedDB.Abstractions;
using MT.Blazor.IndexedDB.Interop;

namespace MT.Blazor.IndexedDB;

public class IndexedMap : IIndexedStore
{
    private readonly IndexedDbContext _context;
    private readonly StoreSchema _schema;

    public string StoreName => _schema.Name;

    public IndexedMap(IndexedDbContext context, StoreSchema schema)
    {
        _context = context;
        _schema = schema;
    }

    public async Task<Dictionary<object, object>> GetAllAsync()
    {
        var keys = await _context.GetAllKeys<object>(_schema.Name);
        var values = await _context.GetAll<object>(_schema.Name);

        return keys.Select((key, index) => (key, values[index]))
            .ToDictionary(x => x.key, x => x.Item2);
    }
        
    public async Task<TValue> GetAsync<TKey, TValue>(TKey key) where TKey : IConvertible
    {
        var storedKey = await _context.GetKey(_schema.Name, key); 
            
        return storedKey != null
            ? await _context.Get<TKey, TValue>(_schema.Name, key)
            : default;   
    }

    public async Task SetAsync<TKey, TValue>(TKey key, TValue value) where TKey : IConvertible
        => await _context.PutValue(_schema.Name, key, value);

    public async Task<int> CountAsync()
        => await _context.Count(_schema.Name);

    public async Task DeleteAsync<TKey>(TKey key) where TKey : IConvertible
        => await _context.Delete(_schema.Name, key);
        
    public async Task ClearAsync()
        => await _context.Clear(_schema.Name);
}