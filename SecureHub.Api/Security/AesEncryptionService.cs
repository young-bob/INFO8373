using System.Security.Cryptography;
using System.Text;

namespace SecureHub.Api.Security;

public class AesEncryptionService
{
    private readonly byte[] _key;

    public AesEncryptionService(string base64Key)
    {
        if (string.IsNullOrWhiteSpace(base64Key))
        {
            throw new ArgumentNullException(nameof(base64Key), "Encryption key must be provided.");
        }
        
        _key = Convert.FromBase64String(base64Key);
        if (_key.Length != 32)
        {
            throw new ArgumentException("Key must be 32 bytes (256-bit) base64 string for AES-256.");
        }
    }

    public string Encrypt(string plainText)
    {
        if (string.IsNullOrEmpty(plainText))
            return plainText;

        using var aes = Aes.Create();
        aes.Key = _key;
        aes.GenerateIV();
        
        using var encryptor = aes.CreateEncryptor(aes.Key, aes.IV);
        using var ms = new MemoryStream();
        ms.Write(aes.IV, 0, aes.IV.Length); // Prepend IV
        
        using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
        using (var sw = new StreamWriter(cs, Encoding.UTF8))
        {
            sw.Write(plainText);
        }
        
        return Convert.ToBase64String(ms.ToArray());
    }

    public string Decrypt(string cipherText)
    {
        if (string.IsNullOrEmpty(cipherText))
            return cipherText;

        var fullCipher = Convert.FromBase64String(cipherText);
        using var ms = new MemoryStream(fullCipher);
        
        var iv = new byte[16];
        int bytesRead = ms.Read(iv, 0, iv.Length);
        if (bytesRead < iv.Length)
        {
            throw new CryptographicException("Cipher text is too short.");
        }
        
        using var aes = Aes.Create();
        aes.Key = _key;
        aes.IV = iv;
        
        using var decryptor = aes.CreateDecryptor(aes.Key, aes.IV);
        using var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read);
        using var sr = new StreamReader(cs, Encoding.UTF8);
        
        return sr.ReadToEnd();
    }

    public async Task EncryptStreamAsync(Stream inputStream, Stream outputStream)
    {
        using var aes = Aes.Create();
        aes.Key = _key;
        aes.GenerateIV();
        
        // Write IV unencrypted to the head of the file
        await outputStream.WriteAsync(aes.IV, 0, aes.IV.Length);
        
        using var encryptor = aes.CreateEncryptor(aes.Key, aes.IV);
        using var cs = new CryptoStream(outputStream, encryptor, CryptoStreamMode.Write, leaveOpen: true);
        await inputStream.CopyToAsync(cs);
        await cs.FlushFinalBlockAsync();
    }

    public async Task DecryptStreamAsync(Stream inputStream, Stream outputStream)
    {
        var iv = new byte[16];
        int bytesRead = await inputStream.ReadAsync(iv, 0, iv.Length);
        if (bytesRead < iv.Length)
        {
            throw new CryptographicException("Cipher text is too short or file is corrupted.");
        }
        
        using var aes = Aes.Create();
        aes.Key = _key;
        aes.IV = iv;
        
        using var decryptor = aes.CreateDecryptor(aes.Key, aes.IV);
        using var cs = new CryptoStream(inputStream, decryptor, CryptoStreamMode.Read, leaveOpen: true);
        await cs.CopyToAsync(outputStream);
    }
}
