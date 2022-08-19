using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Threading.Tasks;

namespace MT.Blazor.ProtectedStorage;

public class ValueProtectionService : IValueProtectionService
{
    private const string ProtectedValuePrefix = "<protected>:";
        
    private readonly IEncryptionService _encryptionService;

    public ValueProtectionService(IEncryptionService encryptionService)
    {
        _encryptionService = encryptionService;
    }

    public async Task<TValue> ProtectAsync<TValue>(TValue value) where TValue : class
    {
        if (value == null)
        {
            return default;
        }

        var valueType = value.GetType();

        if (TypeIsNotProtective(valueType))
        {
            return value;
        }

        if (valueType.IsProtectedValueType())
        {
            return !CanProtect(value as ProtectedValue)
                ? value
                : await ProtectValueAsync(value as ProtectedValue) as TValue;
        }

        await ProtectProperties(value);

        return value;
    }

    public async Task<TValue> ExposeAsync<TValue>(TValue value) where TValue : class
    {
        if (value == default)
        {
            return null;
        }

        var valueType = value.GetType();
            
        if (TypeIsNotProtective(valueType))
        {
            return value;
        }

        if (valueType.IsProtectedValueType())
        {
            return CanProtect(value as ProtectedValue)
                ? value
                : await ExposeValueAsync(value as ProtectedValue) as TValue;
        }
            
        await ExposeProperties(value);
            
        return value;
    }

    public async Task<ProtectedValue> ExposeAsync(ProtectedValue value)
    {
        if (value == null || CanProtect(value))
        {
            return value;
        }
            
        return await ExposeValueAsync(value);
    }

    private static bool CanProtect(ProtectedValue value)
    {
        return !(((string) value)?.StartsWith(ProtectedValuePrefix) ?? true);
    }

    private static bool TypeIsNotProtective(Type type)
    {
        var genericArgumentType = type.IsGenericType
            ? type.GenericTypeArguments.First()
            : null;
            
        return !type.IsProtectedModelType()
               && !type.IsProtectedValueType()
               && !(genericArgumentType?.IsProtectedModelType() ?? false);
    }

    private async Task ProtectProperties(object value)
    {
        if (value.GetType().IsGenericListType())
        {
            foreach (var item in (IEnumerable<object>) value)
            {
                await ProtectProperties(item);
            }

            return;
        }
            
        var protectedProps = GetProtectedProperties(value)
            .Where(p => CanProtect(p.CurrentValue))
            .ToArray();

        foreach (var (propertyInfo, currentValue) in protectedProps)
        {
            propertyInfo.SetValue(value, await ProtectValueAsync(currentValue));
        }
            
        var nestedProtectedModels = GetNestedProtectedModels(value);

        if (nestedProtectedModels?.Any() ?? false)
        {
            foreach (var nestedModel in nestedProtectedModels)
            {
                await ProtectProperties(nestedModel);
            }
        }
    }

    private async Task ExposeProperties(object value)
    {
        if (value.GetType().IsGenericListType())
        {
            foreach (var item in (IEnumerable<object>) value)
            {
                await ExposeProperties(item);
            }

            return;
        }
            
        var protectedProps = GetProtectedProperties(value)
            .Where(p => !CanProtect(p.CurrentValue))
            .ToArray();

        foreach (var (propertyInfo, currentValue) in protectedProps)
        {
            propertyInfo.SetValue(value, await ExposeAsync(currentValue));
        }
            
        var nestedProtectedModels = GetNestedProtectedModels(value);

        if (nestedProtectedModels?.Any() ?? false)
        {
            foreach (var nestedModel in nestedProtectedModels)
            {
                await ExposeProperties(nestedModel);
            }
        }
    }
        
    private async Task<ProtectedValue> ProtectValueAsync(ProtectedValue value)
    {
        return new ProtectedValue($"{ProtectedValuePrefix}{await _encryptionService.EncryptAsync(value)}");
    }

    private async Task<ProtectedValue> ExposeValueAsync(ProtectedValue value)
    {
        return new ProtectedValue(await _encryptionService.DecryptAsync(value.ToString().Replace(ProtectedValuePrefix, "")));
    }

    private static IEnumerable<(PropertyInfo PropertyInfo, ProtectedValue CurrentValue)> GetProtectedProperties(object valueObject)
    {
        var valueObjectType = valueObject.GetType();
        var publicProps = valueObjectType.GetProperties(BindingFlags.Public | BindingFlags.Instance | BindingFlags.FlattenHierarchy);
            
        return publicProps 
            .Where(p => p.PropertyType.IsProtectedValueType())
            .Select(p => (PropertyInfo: p, CurrentValue: (ProtectedValue) p.GetValue(valueObject)));
    }

    private static object[] GetNestedProtectedModels(object valueObject)
    {
        var valueObjectType = valueObject.GetType();
        var publicProps = valueObjectType.GetProperties(BindingFlags.Public | BindingFlags.Instance | BindingFlags.FlattenHierarchy);
            
        return publicProps 
            .Where(p => p.PropertyType.IsProtectedModelType())
            .Select(p => p.GetValue(valueObject))
            .ToArray();
    }

}
    
internal static class ValueTypeExtensions
{
    internal static bool IsProtectedModelType(this Type type) => 
        typeof(IProtectedModel).IsAssignableFrom(type);

    internal static bool IsProtectedValueType(this Type type) =>
        type == typeof(ProtectedValue);

    internal static bool IsGenericListType(this Type type) =>
        type.IsGenericType && type.GetGenericTypeDefinition() == typeof(List<>);
}