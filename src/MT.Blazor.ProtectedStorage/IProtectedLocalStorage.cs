using System.Threading;
using System.Threading.Tasks;

namespace MT.Blazor.ProtectedStorage;

public interface IProtectedLocalStorage
{
    ValueTask ClearAsync(CancellationToken? cancellationToken = null);

    ValueTask<T> GetItemAsync<T>(string key, CancellationToken? cancellationToken = null) where T : class;

    ValueTask<string> SetItemAsync<T>(string key, T data, CancellationToken? cancellationToken = null) where T : class;

    ValueTask<T> GetValueAsync<T>(string key, CancellationToken? cancellationToken = null);

    ValueTask SetValueAsync<T>(string key, T data, CancellationToken? cancellationToken = null);

    ValueTask<string> GetStringValueAsync(string key, CancellationToken? cancellationToken = null);

    ValueTask SetStringValueAsync(string key, string data, CancellationToken? cancellationToken = null);

    ValueTask<bool> ContainKeyAsync(string key, CancellationToken? cancellationToken = null);

    ValueTask RemoveItemAsync(string key, CancellationToken? cancellationToken = null);
}