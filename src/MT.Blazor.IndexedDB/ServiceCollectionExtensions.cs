using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using MT.Blazor.IndexedDB.Interop;

namespace MT.Blazor.IndexedDB;

public static class ServiceCollectionExtensions
{
    public static IServiceCollection AddIndexedDbContext<TContext>(this IServiceCollection services, string databaseName) where TContext : IndexedDbContext
    {
        services.AddSingleton<IIndexedDbConnector, IndexedDbConnector>();
        services.TryAddScoped(sp => ActivatorUtilities.CreateInstance<TContext>(sp, new DbSchema { Name = databaseName, Version = 1 }));

        return services;
    }
}