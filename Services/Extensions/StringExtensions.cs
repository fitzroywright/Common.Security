namespace Common.Security.Services.Extensions
{
    using System.Text;

    public static class StringExtensions
    {
        public static string GetSubstringBefore(this string input, char delimiter)
        {
            if (string.IsNullOrEmpty(input)) return input;
            int index = input.AsSpan().IndexOf(delimiter);
            return index >= 0 ? input[..index] : input;
        }

        public static ReadOnlySpan<char> GetSubstringBefore(this ReadOnlySpan<char> input, char delimiter)
        {
            int index = input.IndexOf(delimiter);
            return index >= 0 ? input[..index] : input;
        }

        public static string GetSubstringAfter(this string input, char delimiter)
        {
            if (string.IsNullOrEmpty(input)) return input;
            ReadOnlySpan<char> span = input.AsSpan();
            int index = span.IndexOf(delimiter);
            if (index < 0) return input;
            return index + 1 < span.Length ? span[(index + 1)..].ToString() : string.Empty;
        }

        public static string GetSubstringBetween(this string input, char start, char end)
        {
            if (string.IsNullOrEmpty(input)) return string.Empty;
            ReadOnlySpan<char> span = input.AsSpan();
            int startIndex = span.IndexOf(start);
            if (startIndex < 0 || startIndex + 1 >= span.Length) return string.Empty;
            int endIndex = span.Slice(startIndex + 1).IndexOf(end);
            if (endIndex < 0) return string.Empty;
            return span.Slice(startIndex + 1, endIndex).ToString();
        }

        public static ReadOnlySpan<char> GetSubstringBetween(this ReadOnlySpan<char> input, char start, char end)
        {
            int startIndex = input.IndexOf(start);
            if (startIndex < 0 || startIndex + 1 >= input.Length) return ReadOnlySpan<char>.Empty;
            ReadOnlySpan<char> sliceAfterStart = input[(startIndex + 1)..];
            int endIndex = sliceAfterStart.IndexOf(end);
            return endIndex >= 0 ? sliceAfterStart[..endIndex] : ReadOnlySpan<char>.Empty;
        }

        public static string? Truncate(this string? value, int maxLength)
        {
            if (maxLength < 0) throw new ArgumentOutOfRangeException(nameof(maxLength));
            if (string.IsNullOrWhiteSpace(value)) return value;
            return value.Length <= maxLength ? value.Trim() : value.Substring(0, maxLength).Trim();
        }

        public static bool IsNullOrBlank(this string? input) => string.IsNullOrWhiteSpace(input);

        private const char spaceChar = ' ';

        public static string NormalizeWhitespace(this string input)
        {
            if (string.IsNullOrWhiteSpace(input)) return string.Empty;
            var sb = new StringBuilder(input.Length);
            bool previousWasWhitespace = false;
            foreach (char c in input)
            {
                if (char.IsWhiteSpace(c))
                {
                    if (!previousWasWhitespace)
                    {
                        sb.Append(spaceChar);
                        previousWasWhitespace = true;
                    }
                }
                else
                {
                    sb.Append(c);
                    previousWasWhitespace = false;
                }
            }
            return sb.ToString().Trim();
        }
    }
}
