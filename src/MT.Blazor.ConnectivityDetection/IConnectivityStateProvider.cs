using System.Threading.Tasks;

namespace MT.Blazor.ConnectivityDetection;

public interface IConnectivityStateProvider
{
    Task StartConnectivityDetectionAsync();
        
    Task StopConnectivityDetectionAsync();
        
    /// <summary>
    /// Asynchronously gets an <see cref="ConnectivityState"/> that describes the current connectivity status.
    /// </summary>
    /// <returns>A task that, when resolved, gives an <see cref="ConnectivityState"/> instance that describes the current connectivity status.</returns>
    Task<ConnectivityState> GetConnectivityStateAsync();
        
    /// <summary>
    /// An event that provides notification when the <see cref="ConnectivityState"/>
    /// has changed. For example, this event may be raised if user goes offline
    /// </summary>
    event ConnectivityStateChangedHandler ConnectivityStateChanged;
}
    
public delegate void ConnectivityStateChangedHandler(ConnectivityState state);