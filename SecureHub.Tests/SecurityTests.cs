using FluentAssertions;
using SecureHub.Api.Security;
using System.IO;
using System.Threading.Tasks;

namespace SecureHub.Tests;

public class SecurityTests
{
    [Fact]
    public void PasswordHasher_ShouldGenerateValidBcryptHash_AndVerifyProperly()
    {
        // Arrange
        var plainPassword = "SuperSecretPassword123!";

        // Act
        var hash = PasswordHasher.HashPassword(plainPassword);
        var isValid = PasswordHasher.VerifyPassword(plainPassword, hash);
        var isInvalid = PasswordHasher.VerifyPassword("WrongPassword!", hash);

        // Assert
        hash.Should().NotBeNullOrEmpty();
        isValid.Should().BeTrue("Because the correct password was used.");
        isInvalid.Should().BeFalse("Because the wrong password should be rejected.");
    }

    [Fact]
    public void AesEncryptionService_ShouldEncryptAndDecryptStrings_Properly()
    {
        // Arrange
        var aesKey = "MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE="; // 32 bytes base64 standard key
        var service = new AesEncryptionService(aesKey);
        var plainText = "Sensitive Data Needs To Be Hidden!";

        // Act
        var cipherText = service.Encrypt(plainText);
        var decryptedText = service.Decrypt(cipherText);

        // Assert
        cipherText.Should().NotBe(plainText);
        decryptedText.Should().Be(plainText);
    }
    
    [Fact]
    public async Task AesEncryptionService_ShouldEncryptAndDecryptStreams_Properly()
    {
        // Arrange
        var aesKey = "MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE="; 
        var service = new AesEncryptionService(aesKey);
        var sourceBytes = System.Text.Encoding.UTF8.GetBytes("Data within a Stream File! Tested against CBC padding block architectures.");
        
        using var memInput = new MemoryStream(sourceBytes);
        using var memEncrypted = new MemoryStream();
        using var memDecrypted = new MemoryStream();

        // Act
        await service.EncryptStreamAsync(memInput, memEncrypted);
        memEncrypted.Position = 0; // Reset
        await service.DecryptStreamAsync(memEncrypted, memDecrypted);

        // Assert
        memEncrypted.ToArray().Length.Should().BeGreaterThan(sourceBytes.Length);
        System.Text.Encoding.UTF8.GetString(memDecrypted.ToArray()).Should().Be("Data within a Stream File! Tested against CBC padding block architectures.");
    }
}
