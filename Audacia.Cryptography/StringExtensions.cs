using System.Collections.Generic;
using System.Text;

namespace Audacia.Cryptography
{
    public static class StringExtensions
    {
        /// <summary>
        /// Splits a string based on a char delimiter, looping over each character individually and ignoring the delimiter in return strings.
        /// Preferred for larger strings as String.Split will allocate too much memory on the LOH
        /// </summary>
        /// <param name="str">String to split</param>
        /// <param name="delimiter">Char to ignore and split on</param>
        /// <returns>Array of substrings</returns>
        public static string[] LowMemorySplit(this string str, char delimiter)
        {
            var result = new List<string>();
            var sb = new StringBuilder();
            foreach (var c in str)
            {
                if (c == delimiter)
                {
                    result.Add(sb.ToString());
                    sb.Clear();
                    continue;
                }
                sb.Append(c);
            }

            result.Add(sb.ToString());

            return result.ToArray();
        }
    }
}