namespace MT.Blazor.ConnectivityDetection;

public class ConnectivityOptions
{
    public string PingUrl { get; set; }

    public int PingInterval { get; set; } = 30000;
}