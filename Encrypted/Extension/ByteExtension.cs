using System;
using System.Collections.Generic;
using System.Text;

namespace EncryptionLib.Extension
{
    public static class ByteExtension
    {
        //Encoding.UTF8.GetString(HttpContext.Session.Get("CLIENT_AES_KEY"));
        public static string ToUTF8String(this byte[] data)
        {
            return Encoding.UTF8.GetString(data);
        }
    }
}
