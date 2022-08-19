using System;
using System.Collections.Generic;
using System.Linq.Expressions;
using System.Threading.Tasks;
using MT.Blazor.IndexedDB.Abstractions;
using MT.Blazor.IndexedDB.Interop;

namespace MT.Blazor.IndexedDB;

public class IndexedSet<TEntity> : IIndexedStore where TEntity : new()
{
    private readonly IndexedDbContext _context;
    private readonly StoreSchema _schema;

    public string StoreName => _schema.Name;
        
    public IndexedSet(IndexedDbContext context, StoreSchema schema)
    {
        _context = context;
        _schema = schema;
    }

    public async Task<TEntity> FindAsync<TKey>(TKey key) 
        => await _context.Get<TKey, TEntity>(_schema.Name, key);

    public async Task<TEntity> FirstAsync<TKey>(params Expression<Func<TEntity, bool>>[] predicates) 
        => await _context.First(_schema.Name, predicates);

    public async Task<TEntity> FirstFromIndexAsync<TInput>(string indexName, TInput queryValue, params Expression<Func<TEntity, bool>>[] predicates) 
        => await _context.GetFromIndex(_schema.Name, indexName, queryValue, predicates);
        
    public async Task<bool> Has<TKey>(TKey key)
        => await _context.GetKey(_schema.Name, key) != null;

    public async Task<List<TEntity>> GetAllAsync(params Expression<Func<TEntity, bool>>[] predicates)
        => await _context.GetAll(_schema.Name, predicates);
        
    public async Task<List<TEntity>> GetAllAsync<TInput>(TInput queryValue, params Expression<Func<TEntity, bool>>[] predicates)
        => await _context.GetAll(_schema.Name, queryValue, predicates);

    public async Task<List<TEntity>> GetAllFromIndexAsync<TInput>(string indexName, TInput queryValue, params Expression<Func<TEntity, bool>>[] predicates)
        => await _context.GetAllFromIndex(_schema.Name, indexName, queryValue, predicates);
        
    public async Task<int> CountAsync()
        => await _context.Count(_schema.Name);

    public async Task<int> CountFromIndexAsync<TKey>(string indexName, TKey key)
        => await _context.CountFromIndex(_schema.Name, indexName, key);

    public async Task PutAsync(TEntity item)
        => await _context.Put(_schema.Name, item);
        
    public async Task PutAllAsync(IEnumerable<TEntity> items)
        => await _context.PutAll(_schema.Name, items);
        
    public async Task DeleteAsync<TKey>(params TKey[] key)
        => await _context.Delete(_schema.Name, key);
        
    public async Task DeleteAllFromIndexAsync<TInput>(string indexName, TInput queryValue)
        => await _context.DeleteAllFromIndex(_schema.Name, indexName, queryValue);
        
    public async Task ClearAsync()
        => await _context.Clear(_schema.Name);
}