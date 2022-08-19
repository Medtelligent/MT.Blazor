using System;
using System.Threading.Tasks;
using Microsoft.JSInterop;

namespace MT.Blazor.ProtectedStorage;

public class EncryptionService : IEncryptionService, IAsyncDisposable
{
    private readonly Lazy<Task<IJSObjectReference>> _jsModuleTask;
        
    private string Key { get; }
        
    public EncryptionService(IJSRuntime jsRuntime, string key)
    {
        Key = key;
            
        _jsModuleTask = new Lazy<Task<IJSObjectReference>>(() => jsRuntime.InvokeAsync<IJSObjectReference>("import", "./_content/MT.Blazor.ProtectedStorage/protectedStorageInterop.js").AsTask());
    }
        
    public async Task<string> EncryptAsync(string input)
    {
        var jsModule = await _jsModuleTask.Value;
            
        return string.IsNullOrEmpty(input)
            ? input
            : await jsModule.InvokeAsync<string>("encrypt", input, Key);
    }

    public async Task<string> DecryptAsync(string encryptedText)
    {
        var jsModule = await _jsModuleTask.Value;
            
        return string.IsNullOrEmpty(encryptedText)
            ? encryptedText
            : await jsModule.InvokeAsync<string>("decrypt", encryptedText, Key);
    }

    public async ValueTask DisposeAsync()
    {
        if (_jsModuleTask.IsValueCreated)
        {
            var module = await _jsModuleTask.Value;
            await module.DisposeAsync();
        }
    }
}