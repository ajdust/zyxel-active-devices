using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace ZyxelActiveDevices
{
    public class Util
    {
        public static string Encrypt(string text, string key)
        {
            var sb = new StringBuilder(128);
            using var mem = new MemoryStream();
            {
                using var aes = new AesManaged();
                aes.Key = FromHex(key);
                sb.Append(ToHex(aes.IV));
                using var enc = aes.CreateEncryptor();
                using var cry = new CryptoStream(mem, enc, CryptoStreamMode.Write);
                using var stw = new StreamWriter(cry);
                stw.Write(text);
            }
	
            sb.Append(ToHex(mem.ToArray()));
            return sb.ToString();
        }

        public static string Decrypt(string ciphertext, string key)
        {
            using var aes = new AesManaged();
            using var dec = aes.CreateDecryptor(FromHex(key), FromHex(ciphertext[..32]));
            using var mem = new MemoryStream(FromHex(ciphertext[32..]));
            using var cry = new CryptoStream(mem, dec, CryptoStreamMode.Read);
            using var reader = new StreamReader(cry);
            return reader.ReadToEnd();
        }

        static string ToHex(byte[] bs) => BitConverter.ToString(bs).Replace("-", "");

        static byte[] FromHex(string hex)
        {
            if (hex.Length % 2 == 1)
                throw new Exception("The binary key cannot have an odd number of digits");

            var arr = new byte[hex.Length >> 1];
            for (var i = 0; i < hex.Length >> 1; ++i)
                arr[i] = (byte)((GetHexVal(hex[i << 1]) << 4) + (GetHexVal(hex[(i << 1) + 1])));

            return arr;
        }

        static int GetHexVal(char hex)
        {
            var val = (int)hex;
            //For uppercase A-F letters:
            //return val - (val < 58 ? 48 : 55);
            //For lowercase a-f letters:
            //return val - (val < 58 ? 48 : 87);
            //Or the two combined, but a bit slower:
            return val - (val < 58 ? 48 : (val < 97 ? 55 : 87));
        }
    }
}