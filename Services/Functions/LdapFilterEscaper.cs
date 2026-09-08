namespace Common.Security.Services.Functions
{
    using System.Text;

    public static class LdapFilterEscaper
    {
        public static string Escape(string? value)
        {
            if (string.IsNullOrEmpty(value))
                return string.Empty;

            StringBuilder? builder = null;

            for (int i = 0; i < value.Length; i++)
            {
                string? escaped = value[i] switch
                {
                    '\\' => @"\5c",
                    '*' => @"\2a",
                    '(' => @"\28",
                    ')' => @"\29",
                    '\0' => @"\00",
                    _ => null
                };

                if (escaped == null)
                {
                    builder?.Append(value[i]);
                    continue;
                }

                builder ??= new StringBuilder(value.Length + 8).Append(value, 0, i);
                builder.Append(escaped);
            }

            return builder?.ToString() ?? value;
        }
    }
}
