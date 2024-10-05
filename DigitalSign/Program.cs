using System.Security.Cryptography;
using System.Text;

namespace DigitalSign
{
    internal class Program
    {
        static void Main(string[] args)
        {
            string data = "Sensitive Information";

            byte[] dataBytes = Encoding.UTF8.GetBytes(data);

            using (RSA rsa = RSA.Create())
            {
                RSAParameters privateKey = rsa.ExportParameters(true);
                RSAParameters publicKey = rsa.ExportParameters(false);

                //sign data
                byte[] signature = SignData(dataBytes, privateKey);

                //verify signature
                bool isValid = VerifySignature(dataBytes, signature, publicKey);

                Console.WriteLine("Valid: " + isValid);
            }
        }

        static byte[] SignData(byte[] data, RSAParameters privateKey)
        {
            using (RSA rsa = RSA.Create())
            {
                rsa.ImportParameters(privateKey);
                return rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            }
        }
        static bool VerifySignature(byte[] data, byte[] signature, RSAParameters publicKey)
        {
            using (RSA rsa = RSA.Create())
            {
                rsa.ImportParameters(publicKey);
                return rsa.VerifyData(data, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            }
        }
    }
}
