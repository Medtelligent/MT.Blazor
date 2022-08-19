using System;
using System.Threading.Tasks;
using Ardalis.GuardClauses;
using Microsoft.JSInterop;

namespace MT.Blazor.ConnectivityDetection;

public class ConnectivityStateProvider : IConnectivityStateProvider, IAsyncDisposable
{
    private readonly ConnectivityOptions _connectivityOptions;
    private readonly Lazy<Task<IJSObjectReference>> _jsModuleTask;

    public ConnectivityStateProvider(IJSRuntime jsRuntime, ConnectivityOptions connectivityOptions)
    {
        _connectivityOptions = connectivityOptions;
        _jsModuleTask = new Lazy<Task<IJSObjectReference>>(() => jsRuntime.InvokeAsync<IJSObjectReference>("import", "./_content/MT.Blazor.ConnectivityDetection/connectivityInterop.js").AsTask());
    }

    public async Task StartConnectivityDetectionAsync()
    {
        var jsModule = await _jsModuleTask.Value;
            
        await jsModule.InvokeVoidAsync("start", new
        {
            Worker = "/_content/MT.Blazor.ConnectivityDetection/workers/connectivityDetector.js",
            Ping = !_connectivityOptions.PingUrl.IsNullOrEmpty()
                ? new 
                {
                    Url = _connectivityOptions.PingUrl,
                    Interval = _connectivityOptions.PingInterval.NullIfDefault() ?? 30000
                }
                : null,
            Callback = new
            {
                Instance = DotNetObjectReference.Create(this),
                MethodName = "ConnectivityChange"
            }
        });
    }

    public async Task StopConnectivityDetectionAsync()
    {
        var jsModule = await _jsModuleTask.Value;
            
        await jsModule.InvokeVoidAsync("stop");
    }

    public async Task<ConnectivityState> GetConnectivityStateAsync()
    {
        var jsModule = await _jsModuleTask.Value;
            
        var info = await jsModule.InvokeAsync<ConnectivityStatusInfo>("status");

        return await Task.FromResult(GetStateFromInfo(info));
    }
        
    public event ConnectivityStateChangedHandler ConnectivityStateChanged;
        
    [JSInvokable]
    public void ConnectivityChange(ConnectivityStatusInfo info)
    {
        NotifyConnectivityStateChanged(GetStateFromInfo(info));
    }

    private void NotifyConnectivityStateChanged(ConnectivityState state)
    {
        Guard.Against.Null(state, nameof(state));

        ConnectivityStateChanged?.Invoke(state);
    }

    private static ConnectivityState GetStateFromInfo(ConnectivityStatusInfo info)
    {
        return new ConnectivityState
        (
            info.Status.IsNullOrEmpty()
                ? ConnectivityState.ConnectivityStatus.Unknown
                : Enum.Parse<ConnectivityState.ConnectivityStatus>(info.Status)
        )
        {
            CheckType = info.CheckType,
            Latency = info.Latency
        };
    }

    public async ValueTask DisposeAsync()
    {
        if (_jsModuleTask.IsValueCreated)
        {
            var module = await _jsModuleTask.Value;
            await module.DisposeAsync();
        }
    }

    public class ConnectivityStatusInfo
    {
        public string Status { get; set; }

        public string CheckType { get; set; }

        public float? Latency { get; set; }
    }
}