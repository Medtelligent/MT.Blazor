using System.Threading.Tasks;

namespace MT.Blazor.IndexedDB.Abstractions;

public interface IIndexedStore
{
    string StoreName { get; }

    Task<int> CountAsync();

    Task ClearAsync();
}