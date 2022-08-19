using System;
using System.Linq;
using System.Reflection;
using System.Text.Json;
using Blazored.LocalStorage;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.JSInterop;
using MT.Blazor.ProtectedStorage.JsonConverters;

namespace MT.Blazor.ProtectedStorage;

public static class ServiceCollectionExtensions
{
    public static IServiceCollection AddProtectedStorage(this IServiceCollection services, string encryptionKey, JsonSerializerOptions jsonSerializerOptions = null)
    {
        services.AddBlazoredLocalStorage(options =>
            {
                options.JsonSerializerOptions.Converters.Add(new ProtectedValueConverter());

                if (jsonSerializerOptions == null)
                {
                    return;
                }
                    
                options.JsonSerializerOptions.PropertyNameCaseInsensitive = jsonSerializerOptions.PropertyNameCaseInsensitive;
                options.JsonSerializerOptions.PropertyNamingPolicy = jsonSerializerOptions.PropertyNamingPolicy;

                foreach (var converter in jsonSerializerOptions.Converters.Where(c => c.GetType() != typeof(ProtectedValueConverter)))
                {
                    options.JsonSerializerOptions.Converters.Add(converter);
                }
            })
            .AddScoped<IEncryptionService>(sp => new EncryptionService(sp.GetService<IJSRuntime>(), encryptionKey))
            .AddScoped<IValueProtectionService, ValueProtectionService>()
            .AddScoped<IProtectedLocalStorage, ProtectedLocalStorage>();
            
        return services;
    }
        
    public static IServiceProvider UseProtectedStorage(this IServiceProvider services)
    {
        // @todo: HACK until blazor allows customizing JsonSerializerOptions for IJSRuntime. Ref: https://github.com/dotnet/aspnetcore/issues/12685
        var jsRuntime = services.GetService<IJSRuntime>();
        var jsRuntimeSerializerOptionsProp = typeof(JSRuntime).GetProperty("JsonSerializerOptions", BindingFlags.NonPublic | BindingFlags.Instance);
            
        if (jsRuntimeSerializerOptionsProp == null)
        {
            throw new InvalidOperationException("JSRuntime.JsonSerializerOptions property is missing");
        }
            
        var jsRuntimeSerializerOptions = (JsonSerializerOptions) Convert.ChangeType(jsRuntimeSerializerOptionsProp.GetValue(jsRuntime, null), typeof(JsonSerializerOptions));

        if (jsRuntimeSerializerOptions == null)
        {
            throw new InvalidOperationException("JSRuntime.JsonSerializerOptions value is null");
        }

        jsRuntimeSerializerOptions.Converters.Add(new ProtectedValueConverter());

        return services;
    }
}