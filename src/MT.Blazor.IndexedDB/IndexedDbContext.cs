using System;
using System.Collections.Generic;
using System.Linq;
using System.Linq.Expressions;
using System.Threading.Tasks;
using Microsoft.JSInterop;
using MT.Blazor.IndexedDB.Abstractions;
using MT.Blazor.IndexedDB.Attributes;
using MT.Blazor.IndexedDB.Extensions;
using MT.Blazor.IndexedDB.Interop;

namespace MT.Blazor.IndexedDB;

public abstract class IndexedDbContext : IIndexedDb, IAsyncDisposable
{
    private readonly IIndexedDbConnector _connector;
    private readonly DbSchema _schema;
        
    private Lazy<Task<IJSObjectReference>> _dbConnectionTask;

    public string DatabaseName => _schema.Name;

    public Task ChangeDatabase(string databaseName)
    {
        if (_schema.Name.Equals(databaseName, StringComparison.OrdinalIgnoreCase))
        {
            return Task.CompletedTask;
        }

        _schema.Name = databaseName;
        _dbConnectionTask = new Lazy<Task<IJSObjectReference>>(() => _connector.OpenDb(_schema));
        
        return Task.CompletedTask;
    }

    public List<IIndexedStore> Stores
        => GetType().GetProperties()
            .Where(x => x.PropertyType.IsGenericType && x.PropertyType.GetGenericTypeDefinition() == typeof(IndexedSet<>)
                        || x.PropertyType == typeof(IndexedMap) 
                        || x.PropertyType.IsGenericType && x.PropertyType.GetGenericTypeDefinition() == typeof(IndexedMap<,>))
            .Select(prop => prop.GetValue(this))
            .Cast<IIndexedStore>()
            .ToList();

    protected IndexedDbContext(IIndexedDbConnector connector, DbSchema schema)
    {
        _schema = schema;
        _connector = connector;
        _dbConnectionTask = new Lazy<Task<IJSObjectReference>>(() => _connector.OpenDb(_schema));
            
        BuildSchema();
    }

    public async ValueTask DisposeAsync()
    {
        if (_dbConnectionTask.IsValueCreated)
        {
            await _connector.DisposeAsync();
                
            var connection = await _dbConnectionTask.Value;
            await connection.DisposeAsync();
        }
    }

    internal async Task<TResult> Get<TInput, TResult>(string storeName, TInput key, params Expression<Func<TResult, bool>>[] predicates)
        => await InvokeJsAsync<TResult>(DbFunctions.Get, storeName, key, predicates.ToJavascriptCode());

    internal async Task<TResult> First<TResult>(string storeName, params Expression<Func<TResult, bool>>[] predicates)
        => await InvokeJsAsync<TResult>(DbFunctions.Get, storeName, null, predicates.ToJavascriptCode());

    internal async Task<TResult> GetFromIndex<TInput, TResult>(string storeName, string indexName, TInput searchValue, params Expression<Func<TResult, bool>>[] predicates)
        => await InvokeJsAsync<TResult>(DbFunctions.GetFromIndex, storeName, indexName, searchValue, predicates.ToJavascriptCode());
        
    internal async Task<List<TResult>> GetAll<TResult>(string storeName, params Expression<Func<TResult, bool>>[] predicates)
        => await InvokeJsAsync<List<TResult>>(DbFunctions.GetAll, storeName, null, predicates.ToJavascriptCode());
        
    internal async Task<List<TResult>> GetAll<TInput, TResult>(string storeName, TInput searchValue, params Expression<Func<TResult, bool>>[] predicates)
        => await InvokeJsAsync<List<TResult>>(DbFunctions.GetAll, storeName, searchValue, predicates.ToJavascriptCode());
        
    internal async Task<List<TKey>> GetAllKeys<TKey>(string storeName, TKey key = default)
        => await InvokeJsAsync<List<TKey>>(DbFunctions.GetAllKeys, storeName, key);

    internal async Task<List<TResult>> GetAllFromIndex<TInput, TResult>(string storeName, string indexName, TInput searchValue, params Expression<Func<TResult, bool>>[] predicates)
        => await InvokeJsAsync<List<TResult>>(DbFunctions.GetAllFromIndex, storeName, indexName, searchValue, predicates.ToJavascriptCode());

    internal async Task<int> Count(string storeName, object key = null)
        => await InvokeJsAsync<int>(DbFunctions.Count, storeName, key);
        
    internal async Task<int> CountFromIndex<TInput>(string storeName, string indexName, TInput key)
        => await InvokeJsAsync<int>(DbFunctions.CountFromIndex, storeName, indexName, key);

    internal async Task<TInput> GetKey<TInput>(string storeName, TInput key)
        => await InvokeJsAsync<TInput>(DbFunctions.GetKey, storeName, key);

    internal async Task Put<TInput>(string storeName, TInput data)
        => await InvokeVoidJsAsync(DbFunctions.Put, storeName, data);
        
    internal async Task PutValue<TKey, TValue>(string storeName, TKey key, TValue value)
        => await InvokeVoidJsAsync(DbFunctions.Put, storeName, value, key);

    internal async Task PutAll<TInput>(string storeName, IEnumerable<TInput> data)
        => await InvokeVoidJsAsync(DbFunctions.PutAll, storeName, data);

    internal async Task Delete(string storeName, object key)
        => await InvokeVoidJsAsync(DbFunctions.Delete, storeName, key);

    internal async Task DeleteAllFromIndex<TInput>(string storeName, string indexName, TInput queryValue)
        => await InvokeVoidJsAsync(DbFunctions.DeleteAllFromIndex, storeName, indexName, queryValue);

    internal async Task Clear(string storeName)
        => await InvokeVoidJsAsync(DbFunctions.ClearStore, storeName);
        
    private async Task<TResult> InvokeJsAsync<TResult>(string identifier, params object[] args)
    {
        var connection = await _dbConnectionTask.Value;
        return await connection.InvokeAsync<TResult>(identifier, args);
    }

    private async Task InvokeVoidJsAsync(string identifier, params object[] args)
    {
        var connection = await _dbConnectionTask.Value;
        await connection.InvokeVoidAsync(identifier, args);
    }

    private void BuildSchema()
    {
        var mapStoreProperties = GetType().GetProperties()
            .Where(x => x.PropertyType == typeof(IndexedMap) || x.PropertyType.IsGenericType && x.PropertyType.GetGenericTypeDefinition() == typeof(IndexedMap<,>));

        foreach (var storeProperty in mapStoreProperties)
        {
            var store = new StoreSchema
            {
                Name = FirstToLower(storeProperty.Name),
                IsKeyVal = true
            };

            _schema.Stores.Add(store);
                
            storeProperty.SetValue(this, Activator.CreateInstance(storeProperty.PropertyType, this, store));
        }
            
        var setStoreProperties = GetType().GetProperties()
            .Where(x => x.PropertyType.IsGenericType && x.PropertyType.GetGenericTypeDefinition() == typeof(IndexedSet<>));

        foreach (var storeProperty in setStoreProperties)
        {
            var store = new StoreSchema
            {
                Name = FirstToLower(storeProperty.Name),
                Indexes = new List<IndexSpec>(),
            };

            // Get generic parameter of list<T> (type T, only supports IndexedSet<T> ergo 1 parameter)
            var propertyType = storeProperty.PropertyType.GetGenericArguments()[0];

            // Get all properties of the generic type T
            var properties = propertyType.GetProperties();

            foreach (var property in properties)
            {
                var primaryKeyAttribute = (PrimaryKeyAttribute) Attribute.GetCustomAttribute(property, typeof(PrimaryKeyAttribute)); //attributes.FirstOrDefault(x => x.AttributeType == typeof(PrimaryKeyAttribute));
                var indexAttribute = (IndexAttribute) Attribute.GetCustomAttribute(property, typeof(IndexAttribute)); //attributes.FirstOrDefault(x => x.AttributeType == typeof(IndexAttribute));
                var columnName = FirstToLower(property.Name);

                if (primaryKeyAttribute is not null)
                {
                    if (store.PrimaryKey is not null)
                    {
                        throw new InvalidOperationException("PrimaryKey already defined");
                    }
                        
                    store.PrimaryKey = new IndexSpec
                    {
                        KeyPath = columnName,
                        Auto = primaryKeyAttribute.AutoIncrement
                    };
                }
                else if (indexAttribute is not null)
                {
                    store.Indexes.Add(new IndexSpec
                    {
                        Name = indexAttribute.Name ?? columnName,
                        KeyPath = columnName,
                        Auto = indexAttribute.AutoIncrement,
                        Unique = indexAttribute.Unique,
                        MultiEntry = indexAttribute.MultiEntry
                    });
                }
            }

            if (store.PrimaryKey is null)
            {
                const string idPropertyName = "Id";
                var idColumnName = FirstToLower(idPropertyName);
                var idProperty = properties.FirstOrDefault(x => x.Name.Equals(idPropertyName, StringComparison.OrdinalIgnoreCase));

                // Check for registered id property without declared key attribute
                if (idProperty is not null)
                {
                    var idPropertyIndex = store.Indexes.FirstOrDefault(x => x.Name == idColumnName);

                    if (idPropertyIndex is not null)
                    {
                        store.Indexes.Remove(idPropertyIndex);
                        store.PrimaryKey = idPropertyIndex;
                    }
                    else
                    {
                        store.PrimaryKey = new IndexSpec
                        {
                            KeyPath = idColumnName
                        };
                    }
                }
                else
                {
                    throw new NotSupportedException("Missing PrimaryKey property");
                }
            }

            _schema.Stores.Add(store);
                
            storeProperty.SetValue(this, Activator.CreateInstance(storeProperty.PropertyType, this, store));
        }
    }

    private static string FirstToLower(string input)
    {
        if (input != string.Empty && char.IsUpper(input[0]))
        {
            input = char.ToLower(input[0]) + input[1..];
        }

        return input;
    }
}