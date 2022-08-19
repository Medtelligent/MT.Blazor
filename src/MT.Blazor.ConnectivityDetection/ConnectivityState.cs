namespace MT.Blazor.ConnectivityDetection;

public record ConnectivityState(ConnectivityState.ConnectivityStatus Status)
{
    public string CheckType { get; init; }
        
    public float? Latency { get; init; }
        
    public enum ConnectivityStatus
    {
        Online,
        Offline,
        Slow,
        Unknown
    }
}