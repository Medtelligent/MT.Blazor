namespace MT.Blazor.ProtectedStorage.Extensions;

internal static class StringExtensions
{
    public static bool IsNullOrEmpty(this string self)
    {
        return string.IsNullOrEmpty(self);
    }
        
    public static string NullIfEmpty(this string self)
    {
        return string.IsNullOrWhiteSpace(self) ? null : self;
    }
}