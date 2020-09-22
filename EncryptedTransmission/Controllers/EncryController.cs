using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using EncryptionLib;
using EncryptionLib.Extension;
using EncryptionLibs;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace EncryptedTransmission.Controllers
{
    public class EncryController : Controller
    {
        private readonly RSAEncryption rsaEncryption;
        private readonly AESEncryption aesEncryption;

        public EncryController()
        {
            rsaEncryption = new RSAEncryption(null);
            aesEncryption = new AESEncryption();
        }
        public IActionResult Index()
        {
            return View();
        }

        public JsonResult GetServerKey()
        {
            Console.WriteLine(HttpContext.Session.Id);
            string publicKey = rsaEncryption.GeneratePublicWithXmlFormat();
            string privateKey = rsaEncryption.GeneratePrivateKeyWithXmlFormat();
            string privateKeyString = rsaEncryption.GeneratePublicKeyWithStringFormat();

            HttpContext.Session.Set("PUBLIC_KEY", publicKey.ToBytes());
            HttpContext.Session.Set("PRIVATE_KEY", privateKey.ToBytes());
            HttpContext.Session.Set("PRIVATE_FE_KEY", privateKeyString.ToBytes());

            return new JsonResult(new { code = "200", data = Convert.ToBase64String(privateKeyString.ToBytes()) });
        }

        public JsonResult SetClientKey([FromBody] string key)
        {
            var privateKey = HttpContext.Session.Get("PRIVATE_KEY");
            var decryptString = rsaEncryption.DecryptWithXmlFormat(privateKey.ToUTF8String(), key);
            HttpContext.Session.Set("CLIENT_AES_KEY",decryptString.ToBytes());
            return new JsonResult(new { code = "200"});
        }

        public JsonResult DecryptWihtAES([FromBody] SendData sendData)
        {
            //接收資料並解密
            var clientAseKey = HttpContext.Session.Get("CLIENT_AES_KEY").ToUTF8String();
            var mergeKey = clientAseKey + sendData.ExtendString;
            var decryptString = aesEncryption.AesDecryptBase64(sendData.Data, mergeKey);
            Console.WriteLine("接收資料並解密");
            Console.WriteLine(decryptString);

            //處理資料.....dosomething()
            Console.WriteLine("處理資料.....dosomething()");

            //將處理完的資料加密
            var encryptString = aesEncryption.AesEncryptBase64(decryptString, mergeKey);
            Console.WriteLine("將處理完的資料加密");
            Console.WriteLine(encryptString);
            return new JsonResult(new { code = "200", data = encryptString });
        }
    }
    
    public class SendData
    {
        public string Data { get; set; }
        public string ExtendString { get; set; }
    }
}
