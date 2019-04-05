using System;
using System.Collections.Generic;
using System.Drawing;
using System.Drawing.Imaging;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Base32;
using OtpSharp;
using QRCoder;

namespace TimedOneTimePasswords
{
    class Program
    {
        //private static string secretStr = "5ihtdm6dd7menn7q";
        private static string secretStr = "lnpamdomnnwaucdu";
        private static byte[] secrete = Base32Encoder.Decode(secretStr);
        static void Main(string[] args)
        {
            if(args.Length != 1)
                GenerateCode();

            switch (args[0].ToLower())
            {
                case "generate":
                    GenerateCode();
                    break;
                case "verify":
                    VerifyCode();
                    break;
                case "qr":
                    GenerateSetupCode();
                    break;
            }
            //GenerateSetupCode();
            //VerifyCode();
            GenerateCode();
        }

        static void GenerateCode()
        {
            while (true)
            {    
                var totp = new Totp(secrete);
                var code = totp.ComputeTotp(DateTime.UtcNow);

                Console.WriteLine("Behind:\t\t {0} {1}", totp.ComputeTotp(DateTime.UtcNow.AddSeconds(-30)).Insert(3, " "), totp.RemainingSeconds());
                Console.WriteLine("Current:\t {0} {1}", code.Insert(3, " "), totp.RemainingSeconds());
                Console.WriteLine("Ahead:\t\t {0} {1}", totp.ComputeTotp(DateTime.UtcNow.AddSeconds(30)).Insert(3, " "), totp.RemainingSeconds());
                
                System.Threading.Thread.Sleep(TimeSpan.FromSeconds(1));
                Console.Clear();
            }
        }

        static void VerifyCode()
        {
            while (true)
            {
                Console.Write("Passcode: ");
                var code = Console.ReadLine();
                var totp = new Totp(secrete);
                var result = totp.VerifyTotp(code, out long timeStepMatched, new VerificationWindow(1, 1));

                Console.WriteLine(result);
            }
        }

        static void VerifyCode1()
        {

        }

        static void GenerateSetupCode()
        {
            var value = String.Format("otpauth://totp/{0}?secret={1}&issuer={2}", "CMS", secretStr, "FringeBenefitGroup");

            QRCodeGenerator qrGenerator = new QRCodeGenerator();
            QRCodeData qrCodeData = qrGenerator.CreateQrCode(value, QRCodeGenerator.ECCLevel.Q);
            QRCode qrCode = new QRCode(qrCodeData);
            Bitmap qrCodeImage = qrCode.GetGraphic(20);

            using (var stream = new MemoryStream())
            {
                qrCodeImage.Save(stream, ImageFormat.Jpeg);
                File.WriteAllBytes(@"e:\Brian\Temp\qr.jpg", stream.ToArray());
            }
        }
    }
}
