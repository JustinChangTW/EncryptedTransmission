using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using EncryptionLib;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace EncryptedTransmission.Controllers
{
    public class EncryController : Controller
    {
        private RSAEncryption encryption;

        public EncryController()
        {
            encryption = new RSAEncryption(null);
        }
        public IActionResult Index()
        {
            return View();
        }

        public JsonResult GetServerKey()
        {
            Console.WriteLine("---GetServerKey-------------------------------------------");
            Console.WriteLine(HttpContext.Session.Id);
            string publicKey = encryption.GeneratePublicWithXmlFormat();
            string privateKey = encryption.GeneratePrivateKeyWithXmlFormat();
            string privateKeyString = encryption.GeneratePublicKeyWithStringFormat();
            HttpContext.Session.Set("PUBLIC_KEY", Encoding.UTF8.GetBytes(publicKey));
            HttpContext.Session.Set("PRIVATE_KEY", Encoding.UTF8.GetBytes(privateKey));
            HttpContext.Session.Set("PRIVATE_FE_KEY", Encoding.UTF8.GetBytes(privateKeyString));

            var encryString = encryption.Encryption(publicKey, "1234");
            Console.WriteLine("---encryString---------------------------------------");
            Console.WriteLine(encryString);
            var decryptString = encryption.DecryptWithXmlFormat(privateKey, encryString);
            Console.WriteLine("--decryptString----------------------------------------");
            Console.WriteLine(decryptString);
            //var decryptString2 = encryption.DecryptWithStringFormat(privateKeyString, encryString);

            return new JsonResult(new { code = "200", data = Convert.ToBase64String(Encoding.UTF8.GetBytes(privateKeyString)) });
        }

        public JsonResult SetEncryData([FromBody] string data)
        {
            Console.WriteLine("---SetEncryData-------------------------------------------");
            Console.WriteLine(data);
            Console.WriteLine(HttpContext.Session.Id);
            var privateKey = HttpContext.Session.Get("PRIVATE_KEY");
            var decryptString = encryption.DecryptWithXmlFormat(Encoding.UTF8.GetString(privateKey), data);
            return new JsonResult(new { code = "200", data = decryptString });
        }
    }
}
