namespace Common.Security.Services;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;

/// <summary>Canonical registered-machine proof. Existing PBKDF2 records retain their identifiers and verification format.</summary>
public static class MachineCredentialProof
{
    public static string Hash(string secret)
    {
        if(string.IsNullOrWhiteSpace(secret)||secret.Length>1024) throw new ArgumentException("A bounded machine secret is required.");
        var salt=RandomNumberGenerator.GetBytes(32);
        var hash=Rfc2898DeriveBytes.Pbkdf2(secret,salt,600_000,HashAlgorithmName.SHA256,32);
        return "PBKDF2-SHA256$600000$"+Convert.ToBase64String(salt)+"$"+Convert.ToBase64String(hash);
    }
    public static bool Verify(string encoded,string secret)
    {
        if(string.IsNullOrWhiteSpace(secret)||secret.Length>1024||encoded.Length>300) return false;
        var parts=encoded.Split('$');
        if(parts.Length!=4||parts[0]!="PBKDF2-SHA256"||!int.TryParse(parts[1],NumberStyles.None,CultureInfo.InvariantCulture,out int iterations)||iterations<210_000||iterations>2_000_000) return false;
        try {var salt=Convert.FromBase64String(parts[2]);var expected=Convert.FromBase64String(parts[3]);
            return salt.Length==32 && expected.Length==32 && CryptographicOperations.FixedTimeEquals(expected,Rfc2898DeriveBytes.Pbkdf2(secret,salt,iterations,HashAlgorithmName.SHA256,32));}
        catch(FormatException){return false;}
    }
    /// <summary>For high-entropy keys resolved fresh from the host's existing secret provider.</summary>
    public static bool MatchesSecret(string expected,string supplied)
    {
        if(string.IsNullOrWhiteSpace(expected)||expected.Length>1024||string.IsNullOrWhiteSpace(supplied)||supplied.Length>1024) return false;
        return CryptographicOperations.FixedTimeEquals(SHA256.HashData(Encoding.UTF8.GetBytes(expected)),SHA256.HashData(Encoding.UTF8.GetBytes(supplied)));
    }
}
