using System.Text.Json.Serialization;

namespace MT.Blazor.IndexedDB;

public class IndexedKeyRange<TKey> where TKey : struct
{
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public TKey? Lower { get; init; }
    
    public bool LowerOpen { get; init; }
    
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public TKey? Upper { get; init; }
    
    public bool UpperOpen { get; init; }

    public static IndexedKeyRange<TKey> LowerBound(TKey value, bool open = false)
    {
        return new IndexedKeyRange<TKey>
        {
            Lower = value,
            LowerOpen = open
        };
    }

    public static IndexedKeyRange<TKey> UpperBound(TKey value, bool open = false)
    {
        return new IndexedKeyRange<TKey>
        {
            Upper = value,
            UpperOpen = open
        };
    }

    public static IndexedKeyRange<TKey> Bound(TKey lower, TKey upper, bool lowerOpen = false, bool upperOpen = false)
    {
        return new IndexedKeyRange<TKey>
        {
            Lower = lower,
            LowerOpen = lowerOpen,
            Upper = upper,
            UpperOpen = upperOpen
        };
    }

    public static IndexedKeyRange<TKey> Only(TKey value)
    {
        return new IndexedKeyRange<TKey>
        {
            Lower = value,
            Upper = value
        };
    }
}