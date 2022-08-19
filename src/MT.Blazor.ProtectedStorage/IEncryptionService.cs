using System.Threading.Tasks;

namespace MT.Blazor.ProtectedStorage;

public interface IEncryptionService
{
    Task<string> EncryptAsync(string input);

    Task<string> DecryptAsync(string encryptedText);
}