namespace MT.Blazor.ProtectedStorage;

public class ProtectedValue
{
    private readonly string _value;

    public ProtectedValue()
    {
    }
        
    public ProtectedValue(string value)
    {
        _value = value;
    }

    public static implicit operator ProtectedValue(string value)
    {
        return value switch
        {
            null => null,
            _ => new ProtectedValue(value)
        };
    }

    public static implicit operator string(ProtectedValue value)
    {
        return value?._value;
    }

    public override string ToString()
    {
        return _value;
    }
}