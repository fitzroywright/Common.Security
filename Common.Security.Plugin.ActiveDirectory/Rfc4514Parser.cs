namespace Common.Security.Plugin.ActiveDirectory;

using System.Text;

internal static class Rfc4514Parser
{
    internal static DistinguishedName Parse(string dn)
    {
        if (string.IsNullOrWhiteSpace(dn)) throw new ArgumentNullException(nameof(dn));
        List<RelativeDistinguishedName> rdns = [];
        int i = 0;
        while (i < dn.Length)
        {
            rdns.Add(ParseRdn(dn, ref i));
            if (i < dn.Length && dn[i] == ',') i++;
        }
        if (rdns.Count == 0) throw new FormatException("DN contains no RDNs.");
        return new DistinguishedName(rdns);
    }

    private static RelativeDistinguishedName ParseRdn(string dn, ref int i)
    {
        List<DnAttribute> attributes = [];
        while (true)
        {
            attributes.Add(ParseAttribute(dn, ref i));
            if (i < dn.Length && dn[i] == '+') { i++; continue; }
            break;
        }
        return new RelativeDistinguishedName(attributes);
    }

    private static DnAttribute ParseAttribute(string dn, ref int i)
    {
        SkipSpaces(dn, ref i);
        int start = i;
        while (i < dn.Length && dn[i] != '=') i++;
        string type = dn[start..i];
        if (i >= dn.Length || dn[i] != '=') throw new FormatException("Invalid DN: missing '='");
        i++;
        SkipSpaces(dn, ref i);
        string value = ParseAttributeValue(dn, ref i).Trim();
        SkipSpaces(dn, ref i);
        return new DnAttribute(type, value);
    }

    private static string ParseAttributeValue(string dn, ref int i)
    {
        StringBuilder sb = new();
        if (i < dn.Length && dn[i] == '"')
        {
            i++;
            while (i < dn.Length)
            {
                char c = dn[i++];
                if (c == '"') break;
                if (c == '\\') sb.Append(ParseEscaped(dn, ref i)); else sb.Append(c);
            }
        }
        else
        {
            while (i < dn.Length)
            {
                char c = dn[i];
                if (c == ',' || c == '+') break;
                if (c == '\\') { i++; sb.Append(ParseEscaped(dn, ref i)); }
                else { sb.Append(c); i++; }
            }
        }
        return sb.ToString();
    }

    private static char ParseEscaped(string dn, ref int i)
    {
        if (i >= dn.Length) throw new FormatException("Invalid escape sequence");
        if (IsHex(dn[i]) && i + 1 < dn.Length && IsHex(dn[i + 1]))
        {
            byte value = (byte)((FromHex(dn[i]) << 4) | FromHex(dn[i + 1]));
            i += 2;
            return (char)value;
        }
        return dn[i++];
    }

    private static int FromHex(char c) => c <= '9' ? c - '0' : c <= 'F' ? c - 'A' + 10 : c - 'a' + 10;
    private static bool IsHex(char c) => char.IsAsciiHexDigit(c);
    private static void SkipSpaces(string dn, ref int i) { while (i < dn.Length && dn[i] == ' ') i++; }

    internal sealed record DnAttribute(string Type, string Value);
    internal sealed record RelativeDistinguishedName(IReadOnlyList<DnAttribute> Attributes);
    internal sealed record DistinguishedName(IReadOnlyList<RelativeDistinguishedName> Rdns)
    {
        internal IEnumerable<string> GetValues(string attributeType)
            => Rdns.SelectMany(r => r.Attributes)
                .Where(a => a.Type.Equals(attributeType, StringComparison.OrdinalIgnoreCase))
                .Select(a => a.Value);
    }
}
