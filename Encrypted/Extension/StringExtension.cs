using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace EncryptionLib.Extension
{
    public static class StringExtension
    {
        static MD5CryptoServiceProvider md5 = new MD5CryptoServiceProvider();
        static SHA256CryptoServiceProvider sha256 = new SHA256CryptoServiceProvider();

        public static byte[] ToSha256(this string data)
        {
            return sha256.ComputeHash(Encoding.UTF8.GetBytes(data));
        }

        public static byte[] ToMd5(this string data)
        {
            return md5.ComputeHash(Encoding.UTF8.GetBytes(data));
        }

        public static byte[] ToBytes(this string data)
        {
            return Encoding.UTF8.GetBytes(data);
        }
    }
}
