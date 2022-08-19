using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using MT.Blazor.IndexedDB.Abstractions;
using MT.Blazor.IndexedDB.Interop;

namespace MT.Blazor.IndexedDB;

public class IndexedMap<TKey, TValue> : IIndexedStore where TKey : IConvertible
{
    private readonly IndexedDbContext _context;
    private readonly StoreSchema _schema;

    public string StoreName => _schema.Name;

    public IndexedMap(IndexedDbContext context, StoreSchema schema)
    {
        _context = context;
        _schema = schema;
    }
        
    public async Task<Dictionary<TKey, TValue>> GetAllAsync()
    {
        var keys = await _context.GetAllKeys<TKey>(_schema.Name);
        var values = await _context.GetAll<TValue>(_schema.Name);

        return keys.Select((key, index) => (key, values[index]))
            .ToDictionary(x => x.key, x => x.Item2);
    }

    public async Task<TValue> GetAsync(TKey key)
        => await _context.Get<TKey, TValue>(_schema.Name, key);

    public async Task SetAsync(TKey key, TValue value)
        => await _context.PutValue(_schema.Name, key, value);

    public async Task<int> CountAsync()
        => await _context.Count(_schema.Name);

    public async Task DeleteAsync(params TKey[] key)
        => await _context.Delete(_schema.Name, key);
        
    public async Task ClearAsync()
        => await _context.Clear(_schema.Name);
}