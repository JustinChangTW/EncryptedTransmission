using EncryptionLib.Extension;
using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace EncryptionLibs
{
    public class AESEncryption
    {
        readonly AesCryptoServiceProvider _aes;

        public AESEncryption()
        {
           _aes = new AesCryptoServiceProvider();
        }

        public string AesEncryptBase64(string data, string key)
        {
            string encrypt = "";
            try
            {
                _aes.Key = key.ToSha256(); 
                _aes.IV = key.ToMd5();

                byte[] dataByteArray = Encoding.UTF8.GetBytes(data);
                using (MemoryStream ms = new MemoryStream())
                using (CryptoStream cs = new CryptoStream(ms, _aes.CreateEncryptor(), CryptoStreamMode.Write))
                {
                    cs.Write(dataByteArray, 0, dataByteArray.Length);
                    cs.FlushFinalBlock();
                    encrypt = Convert.ToBase64String(ms.ToArray());
                }
            }
            catch (Exception ex)
            {
                throw ex;
            }
            return encrypt;
        }

        public string AesDecryptBase64(string data, string key)
        {
            string decrypt = "";
            try
            {
                _aes.Key = key.ToSha256();
                _aes.IV = key.ToMd5();

                byte[] dataByteArray = Convert.FromBase64String(data);
                using (MemoryStream ms = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(ms, _aes.CreateDecryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(dataByteArray, 0, dataByteArray.Length);
                        cs.FlushFinalBlock();
                        decrypt = Encoding.UTF8.GetString(ms.ToArray());
                    }
                }
            }
            catch (Exception ex)
            {
                throw new Exception($"AesDercypt Error data:{data}, key:{key}");
            }
            return decrypt;
        }
    }
}
