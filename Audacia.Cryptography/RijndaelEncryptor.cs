using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Audacia.Cryptography
{
    public class RijndaelEncryptor : Encryptor, IDisposable
    {
        public byte[] Key => _cryptoProvider.Key;

        public byte[] Iv => _cryptoProvider.IV;

        private RijndaelManaged _cryptoProvider = new RijndaelManaged();

        private ICryptoTransform _encryptor;

        public RijndaelEncryptor() => _encryptor = _cryptoProvider.CreateEncryptor(_cryptoProvider.Key, _cryptoProvider.IV);

        public RijndaelEncryptor(byte[] key, byte[] iv) => _encryptor = _cryptoProvider.CreateEncryptor(key, iv);

        private byte[] EncryptInternal(string input)
        {
            using (var memoryStream = new MemoryStream())
            using (var cryptoStream = new CryptoStream(memoryStream, _encryptor, CryptoStreamMode.Write))
            {
                using (var writer = new StreamWriter(cryptoStream))
                    writer.Write(input);

                return memoryStream.ToArray();            
            }
        }

        public override string Encrypt(string input)
        {
            var result = EncryptInternal(input);
            return Convert.ToBase64String(result);
        }

        public override byte[] Encrypt(byte[] input)
        {
            var @string = Encoding.UTF8.GetString(input);
            return EncryptInternal(@string);
        }

        public void Dispose()
        {
            _cryptoProvider?.Dispose();
            _encryptor?.Dispose();
        }
    }
}