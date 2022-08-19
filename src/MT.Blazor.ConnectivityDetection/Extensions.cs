namespace MT.Blazor.ConnectivityDetection;

internal static class StringExtensions
{
    public static bool IsNullOrEmpty(this string self)
    {
        return string.IsNullOrEmpty(self);
    }

    public static T? NullIfDefault<T>(this T value) where T : struct
    {
        return Equals(value, default(T)) ? null : value;
    }
}