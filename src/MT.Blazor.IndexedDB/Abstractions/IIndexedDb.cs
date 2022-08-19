using System.Collections.Generic;
using System.Threading.Tasks;

namespace MT.Blazor.IndexedDB.Abstractions;

public interface IIndexedDb
{
    string DatabaseName { get; }

    Task ChangeDatabase(string databaseName);
    
    List<IIndexedStore> Stores { get;  }
}