using System;
using System.Linq;

namespace UPRO.Util
{
    public static class IntExtensions
    {
        public static string PackToHex(this int value, int bytes)
        {
            // 32비트 정수를 리틀 엔디안 방식으로 바이트 배열로 변환
            byte[] byteArray = BitConverter.GetBytes(value).Take(bytes).ToArray();

            // 각 바이트를 16진수 문자열로 변환하고, 공백으로 연결
            return string.Join(" ", byteArray.Select(b => b.ToString("X2")));
        }

        public static int HexLength(this string hexCode)
        {
            if (string.IsNullOrWhiteSpace(hexCode))
                return 0;

            // Split the string by spaces
            var tokens = hexCode.Split(' ');

            // Count valid hex byte tokens (including wildcards)
            return tokens.Count(token => token.Length == 2 && (IsHexByte(token) || IsWildcard(token)));
        }

        private static bool IsHexByte(string token)
        {
            // Check if the token is a valid hex byte (e.g., "6A", "20")
            return token.All(c => Uri.IsHexDigit(c));
        }

        private static bool IsWildcard(string token)
        {
            // Check if the token is a wildcard (e.g., "??")
            return token == "??";
        }
    }
}
