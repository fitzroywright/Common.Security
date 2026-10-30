namespace Common.Security.Services;

using System.Globalization;
using System.Security.Cryptography;

public static class PasswordHasher
{
    public const int Iterations = 600_000;
    public const int MinimumLength = 15;
    public const int MaximumLength = 256;

    public static string Hash(string password)
    {
        if (password is null || password.Length is < MinimumLength or > MaximumLength)
            throw new ArgumentException($"Passwords must contain {MinimumLength} to {MaximumLength} characters.");
        byte[] salt = RandomNumberGenerator.GetBytes(32);
        byte[] hash = Rfc2898DeriveBytes.Pbkdf2(password, salt, Iterations, HashAlgorithmName.SHA256, 32);
        return $"pbkdf2-sha256${Iterations.ToString(CultureInfo.InvariantCulture)}${Convert.ToBase64String(salt)}${Convert.ToBase64String(hash)}";
    }

    public static bool Verify(string? password, string? encoded)
    {
        if (password is null || password.Length > MaximumLength || string.IsNullOrWhiteSpace(encoded) || encoded.Length > 300)
            return false;
        string[] parts = encoded.Split('$');
        if (parts.Length != 4 || parts[0] != "pbkdf2-sha256" ||
            !int.TryParse(parts[1], NumberStyles.None, CultureInfo.InvariantCulture, out int iterations) ||
            iterations is < Iterations or > 2_000_000) return false;
        try
        {
            byte[] salt = Convert.FromBase64String(parts[2]);
            byte[] expected = Convert.FromBase64String(parts[3]);
            if (salt.Length != 32 || expected.Length != 32) return false;
            byte[] actual = Rfc2898DeriveBytes.Pbkdf2(password, salt, iterations, HashAlgorithmName.SHA256, 32);
            return CryptographicOperations.FixedTimeEquals(actual, expected);
        }
        catch (FormatException) { return false; }
    }
}
