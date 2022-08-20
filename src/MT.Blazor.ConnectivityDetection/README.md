# MT.Blazor.ConnectivityDetection
Blazor WASM component library for network connectivity detection

![Nuget](https://img.shields.io/nuget/v/mt.blazor.connectivitydetection.svg)

## Installing

You can install from Nuget using the following command:

`Install-Package MT.Blazor.ConnectivityDetection`

Or via the Visual Studio package manger.

## Basic Usage

Start by add the following using statement to your root `_Imports.razor`.

```razor
@using MT.Blazor.ConnectivityDetection
```

Then add the connectivity state provider in the `App.razor` root component around the `Router`.

```razor
<CascadingConnectivityState>
    <Router AppAssembly="@typeof(Program).Assembly">
        <Found Context="routeData">
            <RouteView RouteData="@routeData" DefaultLayout="@typeof(MainLayout)" />
        </Found>
        <NotFound>
            <p>Sorry, there's nothing at this address.</p>
        </NotFound>
    </Router>
</CascadingConnectivityState>
```

The `CascadingConnectivityState` component subscribes to and starts the network connectivity detection by the `IConnectivityStateProvider` upon initialization 
and notifies nested components of change in network connectivity with  `ConnectivityState`.

The `IConnectivityStateProvider` is the underlying service that subscribes to the javascript based network connectivity detection and provides `ConnectivityState` to subscribers.

## Registering Connectivity Detection

Register and configure connectivity detection in `IServiceCollection` in **`Program.cs`**

```csharp
builder.Services.AddConnectivityDetection();
```

By default, network connectivity state is determine with the browser's `navigator.onLine` information and quality of connection with the [Network Information API](https://developer.mozilla.org/en-US/docs/Web/API/Network_Information_API).  

Since the Network Information API is experimental and has varying browser compatibility, it is highly recommended to configure a HTTP ping check with the `ConnectivityOptions` in the 
`AddConnectivityDetection` method.

```csharp
builder.Services.AddConnectivityDetection(options => 
{
    options.PingUrl = "/api/ping";
    options.PingInterval = 1000;
});
```

These options will start an HTTP based connectivity check in addition to the Network Information API detection every second.  You can configure any API end point to use as a 
ping check, however, it's best to host the end point in the server for an ASP.NET Core hosted Blazor WebAssembly application to have the connectivity state be based on latency 
between with the hosting server application.

## Latency

When performing ping checks, latency is calculated in milliseconds to completion of a successfully HTTP GET to the end point.

With the Network Information API based connectivity detection, due to browser compatibility and the experimental nature of the API, 
the latency value is a static, representative value in milliseconds as follows:

* `effectiveType` value `4g` and `downlink` value of `10` for a fast connection is represented as `50ms`
  * `downlink` value greater than or equal to `5` is represented as `500ms` and `1000ms` otherwise
* `effectiveType` value `3g` is represented as `500ms` and `1000ms` otherwise

When a ping check is configured, then an ad-hoc ping check is performed when the latency measurement as described previously is greater than `50ms` as an accurate verification.

## Connectivity Status

The `ConnectivityState` value that cascades from the `CascadingConnectivityState` as provided by the `IConnectivityStateProvider` conveys the connectivity check type, latency, and 
status to the client application as `ConnectivityStatus` enum value of `Offline`, `Online`, or `Slow`.

The thresholds for the the statuses as as follows:

* `Offline` when `navigator.onLine` is `false` or the ping check fails
* `Online` when latency value is less than `500ms` otherwise `Slow`
  * The `500ms` threshold currently is not configurable

Any service can retrieve the current `ConnectivityState` by injecting the `IConnectivityStateProvider` as a dependency and query the current `ConnectivityState` by calling
the `IConnectivityStateProvider.GetConnectivityStateAsync()` method or by subscribing to the `IConnectivityStateProvider.ConnectivityStateChanged` event.

## Change Log
- 0.0.0 Pre-release
- 1.0.0 Initial release

## Links
[Github Repository](https://github.com/Medtelligent/MT.Blazor) |
[Nuget Package](https://www.nuget.org/packages/MT.Blazor.ConnectivityDetection)