using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Ardalis.GuardClauses;
using Blazored.LocalStorage;
using Blazored.LocalStorage.Serialization;
using MT.Blazor.ProtectedStorage.Extensions;

namespace MT.Blazor.ProtectedStorage;

public class ProtectedLocalStorage : IProtectedLocalStorage
{
    private readonly ILocalStorageService _localStorageService;
    private readonly IValueProtectionService _valueProtector;
    private readonly IJsonSerializer _jsonSerializer;

    public ProtectedLocalStorage(ILocalStorageService localStorageService, IValueProtectionService valueProtector, IJsonSerializer jsonSerializer)
    {
        _localStorageService = localStorageService;
        _valueProtector = valueProtector;
        _jsonSerializer = jsonSerializer;
    }
        
    public async ValueTask ClearAsync(CancellationToken? cancellationToken = null)
        => await _localStorageService.ClearAsync(cancellationToken);
        
    public async ValueTask<T> GetItemAsync<T>(string key, CancellationToken? cancellationToken = null) where T : class
    {
        Guard.Against.NullOrEmpty(key, nameof(key));
            
        var serializedData = await _localStorageService.GetItemAsStringAsync(key, cancellationToken);
            
        if (serializedData.IsNullOrEmpty())
        {
            return default;
        }
            
        try
        {
            var item = _jsonSerializer.Deserialize<T>(serializedData);
                
            return await _valueProtector.ExposeAsync(item);
        }
        catch (JsonException e) when (e.Path == "$" && typeof(T) == typeof(string))
        {
            // For backward compatibility return the plain string.
            // On the next save a correct value will be stored and this Exception will not happen again, for this 'key'
            return (T)(object)serializedData;
        }
    }

    public async ValueTask<string> SetItemAsync<T>(string key, T data, CancellationToken? cancellationToken) where T : class
    {
        Guard.Against.NullOrEmpty(key, nameof(key));
        Guard.Against.Null(data, nameof(data));
            
        await _valueProtector.ProtectAsync(data);
            
        var serializedData = _jsonSerializer.Serialize(data);
        await _localStorageService.SetItemAsStringAsync(key, serializedData, cancellationToken);
            
        return key;
    }

    public async ValueTask<T> GetValueAsync<T>(string key, CancellationToken? cancellationToken = null)
        => await _localStorageService.GetItemAsync<T>(key, cancellationToken);

    public async ValueTask SetValueAsync<T>(string key, T data, CancellationToken? cancellationToken = null)
        => await _localStorageService.SetItemAsync(key, data, cancellationToken);

    public async ValueTask<string> GetStringValueAsync(string key, CancellationToken? cancellationToken = null)
        => await _localStorageService.GetItemAsStringAsync(key, cancellationToken);

    public async ValueTask SetStringValueAsync(string key, string data, CancellationToken? cancellationToken = null)
        => await _localStorageService.SetItemAsStringAsync(key, data, cancellationToken);

    public async ValueTask<bool> ContainKeyAsync(string key, CancellationToken? cancellationToken = null)
        => await _localStorageService.ContainKeyAsync(key, cancellationToken);

    public async ValueTask RemoveItemAsync(string key, CancellationToken? cancellationToken = null)
        => await _localStorageService.RemoveItemAsync(key, cancellationToken);
}