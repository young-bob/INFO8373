using Microsoft.EntityFrameworkCore.Storage.ValueConversion;

namespace SecureHub.Api.Security;

/// <summary>
/// Entity Framework Core Value Converter for transparently encrypting database fields using AES-256.
/// </summary>
public class AesValueConverter : ValueConverter<string?, string?>
{
    public AesValueConverter(AesEncryptionService aesProvider, ConverterMappingHints? mappingHints = null)
        : base(
            v => v == null ? null : aesProvider.Encrypt(v),
            v => v == null ? null : aesProvider.Decrypt(v),
            mappingHints)
    {
    }
}
