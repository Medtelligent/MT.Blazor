using System;
using Microsoft.Extensions.DependencyInjection;

namespace MT.Blazor.ConnectivityDetection;

public static class ServiceCollectionExtensions
{
    public static IServiceCollection AddConnectivityDetection(this IServiceCollection services, Action<ConnectivityOptions> configure = null)
    {
        var options = new ConnectivityOptions();
        configure?.Invoke(options);
            
        services.AddSingleton(options);
            
        services.AddScoped<IConnectivityStateProvider, ConnectivityStateProvider>();

        return services;
    }
}