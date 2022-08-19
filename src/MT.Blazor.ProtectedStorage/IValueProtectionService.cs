using System.Threading.Tasks;

namespace MT.Blazor.ProtectedStorage;

public interface IValueProtectionService
{
    Task<TValue> ProtectAsync<TValue>(TValue value) where TValue : class;

    Task<TValue> ExposeAsync<TValue>(TValue value) where TValue : class;
}