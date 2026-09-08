namespace Common.Security.Services.Functions
{
    using System.Text;
    using Common.Security.Services.Extensions;

    public static class Rfc4514Parser
    {
        public static DistinguishedName Parse(string dn)
        {
            if (dn.IsNullOrBlank()) throw new ArgumentNullException(nameof(dn));
            var rdns = new List<RelativeDistinguishedName>();
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
            var attributes = new List<DnAttribute>();
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
            string type = ParseAttributeType(dn, ref i);
            if (i >= dn.Length || dn[i] != '=') throw new FormatException("Invalid DN: missing '='");
            i++;
            SkipSpaces(dn, ref i);
            string value = ParseAttributeValue(dn, ref i).NormalizeWhitespace();
            SkipSpaces(dn, ref i);
            return new DnAttribute(type, value);
        }

        private static string ParseAttributeType(string dn, ref int i)
        {
            int start = i;
            while (i < dn.Length && dn[i] != '=') i++;
            return dn[start..i];
        }

        private static string ParseAttributeValue(string dn, ref int i)
        {
            var sb = new StringBuilder();
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
        private static void SkipSpaces(string dn, ref int i) { while (i < dn.Length && dn[i] == ' ') i++; }
        private static bool IsHex(char c) => (c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f');
    }

    public sealed record DnAttribute(string Type, string Value);
    public sealed record RelativeDistinguishedName(IReadOnlyList<DnAttribute> Attributes);
    public sealed record DistinguishedName(IReadOnlyList<RelativeDistinguishedName> Rdns)
    {
        public IEnumerable<string> GetValues(string attributeType) => Rdns.SelectMany(r => r.Attributes).Where(a => a.Type.Equals(attributeType, StringComparison.OrdinalIgnoreCase)).Select(a => a.Value);
    }
}
