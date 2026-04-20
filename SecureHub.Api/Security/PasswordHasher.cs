namespace SecureHub.Api.Security;

public static class PasswordHasher
{
    /// <summary>
    /// Hashes a password using Argon2d variant logic built into Enhanced BCrypt format.
    /// Cost factor is set to 13 to defeat parallel GPU brute-forcing.
    /// </summary>
    public static string HashPassword(string password)
    {
        return BCrypt.Net.BCrypt.EnhancedHashPassword(password, 13);
    }

    /// <summary>
    /// Verifies a plain text password against a saved hash securely.
    /// </summary>
    public static bool VerifyPassword(string password, string hash)
    {
        return BCrypt.Net.BCrypt.EnhancedVerify(password, hash);
    }
}
