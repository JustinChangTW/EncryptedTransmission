using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace EncryptionLib
{
    public class RSAEncryption
    {
        private RSACryptoServiceProvider _rsa;

        public RSAEncryption(int? keySize)
        {
            _rsa = new RSACryptoServiceProvider(keySize ?? 2048);
        }

        public string GeneratePrivateKeyWithXmlFormat()
        {
            var privatekey = _rsa.ToXmlString(true);
            return privatekey;
        }

        public string GeneratePublicWithXmlFormat()
        {
            var publicKey = _rsa.ToXmlString(false);
            return publicKey;   
        }

        public string GeneratePublicKeyWithStringFormat()
        {
            var publicKey = ConvertPublicKeyForStringFormat(_rsa.ExportParameters(false));
            return publicKey;
        }

        public string Encryption(string publicKey, string content)
        {
            _rsa.FromXmlString(publicKey);
            return Convert.ToBase64String(_rsa.Encrypt(Encoding.UTF8.GetBytes(content), false));
        }

        public string DecryptWithXmlFormat(string privateKey, string encryptedContent)
        {
            _rsa.FromXmlString(privateKey);
            return Encoding.UTF8.GetString(_rsa.Decrypt(Convert.FromBase64String(encryptedContent), false));
        }

        public string DecryptWithStringFormat(string privateKey, string encryptedContent)
        {
            //string privKeyString = Encoding.ASCII.GetString(Convert.FromBase64String(privateKey));
            var sr = new StringReader(privateKey);
            var xs = new System.Xml.Serialization.XmlSerializer(typeof(RSAParameters));
            var privKey = (RSAParameters)xs.Deserialize(sr);
            _rsa.ImportParameters(privKey);

            return Encoding.UTF8.GetString(_rsa.Decrypt(Convert.FromBase64String(encryptedContent), false));
        }

        //Source: https://stackoverflow.com/questions/17128038/c-sharp-rsa-encryption-decryption-with-transmission
        //This will give public key in the following format which is required by the JS library
        //-----BEGIN PUBLIC KEY-----
        //XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
        //-----END PUBLIC KEY-----
        private string ConvertPublicKeyForStringFormat(RSAParameters publicKey)
        {
            string output = string.Empty;

            using (var stream = new MemoryStream())
            {
                var writer = new BinaryWriter(stream);
                writer.Write((byte)0x30); // SEQUENCE
                using (var innerStream = new MemoryStream())
                {
                    var innerWriter = new BinaryWriter(innerStream);
                    innerWriter.Write((byte)0x30); // SEQUENCE
                    EncodeLength(innerWriter, 13);
                    innerWriter.Write((byte)0x06); // OBJECT IDENTIFIER
                    var rsaEncryptionOid = new byte[] { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01 };
                    EncodeLength(innerWriter, rsaEncryptionOid.Length);
                    innerWriter.Write(rsaEncryptionOid);
                    innerWriter.Write((byte)0x05); // NULL
                    EncodeLength(innerWriter, 0);
                    innerWriter.Write((byte)0x03); // BIT STRING
                    using (var bitStringStream = new MemoryStream())
                    {
                        var bitStringWriter = new BinaryWriter(bitStringStream);
                        bitStringWriter.Write((byte)0x00); // # of unused bits
                        bitStringWriter.Write((byte)0x30); // SEQUENCE
                        using (var paramsStream = new MemoryStream())
                        {
                            var paramsWriter = new BinaryWriter(paramsStream);
                            EncodeIntegerBigEndian(paramsWriter, publicKey.Modulus); // Modulus
                            EncodeIntegerBigEndian(paramsWriter, publicKey.Exponent); // Exponent
                            var paramsLength = (int)paramsStream.Length;
                            EncodeLength(bitStringWriter, paramsLength);
                            bitStringWriter.Write(paramsStream.GetBuffer(), 0, paramsLength);
                        }
                        var bitStringLength = (int)bitStringStream.Length;
                        EncodeLength(innerWriter, bitStringLength);
                        innerWriter.Write(bitStringStream.GetBuffer(), 0, bitStringLength);
                    }
                    var length = (int)innerStream.Length;
                    EncodeLength(writer, length);
                    writer.Write(innerStream.GetBuffer(), 0, length);
                }

                var base64 = Convert.ToBase64String(stream.GetBuffer(), 0, (int)stream.Length);

                StringBuilder sb = new StringBuilder();
                sb.AppendLine("-----BEGIN PUBLIC KEY-----");
                sb.AppendLine(base64);
                sb.AppendLine("-----END PUBLIC KEY-----");

                output = sb.ToString();
            }

            return output;
        }

        private void EncodeLength(BinaryWriter stream, int length)
        {
            if (length < 0) throw new ArgumentOutOfRangeException("length", "Length must be non-negative");
            if (length < 0x80)
            {
                // Short form
                stream.Write((byte)length);
            }
            else
            {
                // Long form
                var temp = length;
                var bytesRequired = 0;
                while (temp > 0)
                {
                    temp >>= 8;
                    bytesRequired++;
                }
                stream.Write((byte)(bytesRequired | 0x80));
                for (var i = bytesRequired - 1; i >= 0; i--)
                {
                    stream.Write((byte)(length >> (8 * i) & 0xff));
                }
            }
        }

        private void EncodeIntegerBigEndian(BinaryWriter stream, byte[] value, bool forceUnsigned = true)
        {
            stream.Write((byte)0x02); // INTEGER
            var prefixZeros = 0;
            for (var i = 0; i < value.Length; i++)
            {
                if (value[i] != 0) break;
                prefixZeros++;
            }
            if (value.Length - prefixZeros == 0)
            {
                EncodeLength(stream, 1);
                stream.Write((byte)0);
            }
            else
            {
                if (forceUnsigned && value[prefixZeros] > 0x7f)
                {
                    // Add a prefix zero to force unsigned if the MSB is 1
                    EncodeLength(stream, value.Length - prefixZeros + 1);
                    stream.Write((byte)0);
                }
                else
                {
                    EncodeLength(stream, value.Length - prefixZeros);
                }
                for (var i = prefixZeros; i < value.Length; i++)
                {
                    stream.Write(value[i]);
                }
            }
        }



    }
}
