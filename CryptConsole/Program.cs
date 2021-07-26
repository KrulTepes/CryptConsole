#nullable enable
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace CryptConsole
{
    internal static class CryptManager
    {
        internal enum Sha3Bitness
        {
            Bit256  = 256,
            Bit512  = 512
        }

        internal enum AESBitness
        {
            Bit128 = 128,
            Bit256 = 256
        }

        internal static string SHA3(string text, Sha3Bitness bitness = Sha3Bitness.Bit256)
        {
            var hashAlgorithm = new Org.BouncyCastle.Crypto.Digests.Sha3Digest((int)bitness);

            byte[] input = Encoding.ASCII.GetBytes(text);

            hashAlgorithm.BlockUpdate(input, 0, input.Length);

            byte[] result = new byte[(int)bitness / 8];
            hashAlgorithm.DoFinal(result, 0);

            string hashString = BitConverter.ToString(result);
            hashString = hashString.Replace("-", "").ToLowerInvariant();

            return hashString;
        }

        internal static string AES(string text, AESBitness bitness = AESBitness.Bit256)
        {
            byte[] encrypted = Array.Empty<byte>();
            try
            {
                using (Rijndael myRijndael = Rijndael.Create())
                {
                    myRijndael.KeySize = (int)bitness;
                    myRijndael.BlockSize = (int)AESBitness.Bit128;
                    encrypted = AES_Encrypt(text, myRijndael.Key, myRijndael.IV);
                }
            }
            catch (Exception e)
            {
                Console.WriteLine("Error: {0}", e.Message);
            }

            string hashString = BitConverter.ToString(encrypted);
            hashString = hashString.Replace("-", "").ToLowerInvariant();
            return hashString;
        }

        internal static byte[] AES_Encrypt(string plainText, byte[] Key, byte[] IV)
        {
            // Check arguments.
            if (plainText == null || plainText.Length <= 0)
                throw new ArgumentNullException("plainText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");
            byte[] encrypted;
            // Create an Rijndael object
            // with the specified key and IV.
            using (Rijndael rijAlg = Rijndael.Create())
            {
                rijAlg.Key = Key;
                rijAlg.IV = IV;

                // Create an encryptor to perform the stream transform.
                ICryptoTransform encryptor = rijAlg.CreateEncryptor(rijAlg.Key, rijAlg.IV);

                // Create the streams used for encryption.
                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {

                            //Write all data to the stream.
                            swEncrypt.Write(plainText);
                        }
                        encrypted = msEncrypt.ToArray();
                    }
                }
            }

            return encrypted;
        }

        internal static string AES_Decrypt(byte[] cipherText, byte[] Key, byte[] IV)
        {
            // Check arguments.
            if (cipherText == null || cipherText.Length <= 0)
                throw new ArgumentNullException("cipherText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");

            // Declare the string used to hold
            // the decrypted text.
            string? plaintext = null;

            // Create an Rijndael object
            // with the specified key and IV.
            using (Rijndael rijAlg = Rijndael.Create())
            {
                rijAlg.Key = Key;
                rijAlg.IV = IV;

                // Create a decryptor to perform the stream transform.
                ICryptoTransform decryptor = rijAlg.CreateDecryptor(rijAlg.Key, rijAlg.IV);

                // Create the streams used for decryption.
                using (MemoryStream msDecrypt = new MemoryStream(cipherText))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                        {

                            // Read the decrypted bytes from the decrypting stream
                            // and place them in a string.
                            plaintext = srDecrypt.ReadToEnd();
                        }
                    }
                }
            }

            return plaintext;
        }
    }
    internal class IOManager
    {
        public void Start()
        {
            Listen();
        }

        private void Listen()
        {
            while (true)
            {
                Console.WriteLine("CryptManager");
                Console.WriteLine("Algorithms:");
                Console.WriteLine("1. SHA3\n2. AES");

                string command = Console.ReadLine() ?? string.Empty;
                switch (command)
                {
                    case "1":
                        {
                            SHA3();
                            break;
                        }
                    case "2":
                        {
                            AES();
                            break;
                        }
                    default:
                        {
                            Console.WriteLine("Error: incorret command\nPress any key");
                            Console.ReadKey();
                            Console.Clear();
                            continue;
                        }
                }
            }
        }

        private static void SHA3()
        {
            Console.Clear();

            while (true)
            {
                Console.WriteLine("SHA3");
                Console.WriteLine($"Bitness (256/512): ");

                string command = Console.ReadLine() ?? string.Empty;
                CryptManager.Sha3Bitness bitness;
                switch (command)
                {
                    case "256":
                        {
                            bitness = CryptManager.Sha3Bitness.Bit256;
                            break;
                        }
                    case "512":
                        {
                            bitness = CryptManager.Sha3Bitness.Bit512;
                            break;
                        }
                    default:
                        {
                            Console.WriteLine("Error: incorret command\nPress any key");
                            Console.ReadKey();
                            Console.Clear();
                            continue;
                        }
                }

                Console.WriteLine($"Text for encrypt: ");
                string textForEncrypt = Console.ReadLine() ?? string.Empty;

                string encrypt = CryptManager.SHA3(textForEncrypt, bitness);

                Console.WriteLine($"Encrypt: {encrypt}\nPress any key");
                Console.ReadKey();
                Console.Clear();
                break;
            }
        }

        private static void AES()
        {
            Console.Clear();

            while (true)
            {
                Console.WriteLine("AES");
                Console.WriteLine($"Bitness (128/256): ");

                string command = Console.ReadLine() ?? string.Empty;
                CryptManager.AESBitness bitness;
                switch (command)
                {
                    case "128":
                        {
                            bitness = CryptManager.AESBitness.Bit128;
                            break;
                        }
                    case "256":
                        {
                            bitness = CryptManager.AESBitness.Bit256;
                            break;
                        }
                    default:
                        {
                            Console.WriteLine("Error: incorret command\nPress any key");
                            Console.ReadKey();
                            Console.Clear();
                            continue;
                        }
                }

                Console.WriteLine($"Text for encrypt: ");
                string textForEncrypt = Console.ReadLine() ?? string.Empty;

                string encrypt = CryptManager.AES(textForEncrypt, bitness);

                Console.WriteLine($"Encrypt: {encrypt}\nPress any key");
                Console.ReadKey();
                Console.Clear();
                break;
            }
        }
    }

    class CryptConsole
    {
        private static IOManager? _ioManagerSingleton;
        private static IOManager IOManager 
        {  
            get
            {
                if (_ioManagerSingleton == null)
                {
                    _ioManagerSingleton = new IOManager();
                }

                return _ioManagerSingleton;
            }
        }

        public static void Main()
        {
            IOManager.Start();
        }
    }
}
