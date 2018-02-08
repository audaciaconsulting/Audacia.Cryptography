using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Audacia.Cryptography
{
    public class RijndaelDecryptor : Decryptor, IDisposable
    {
        public byte[] Key => _cryptoProvider.Key;

        public byte[] Iv => _cryptoProvider.IV;

        private RijndaelManaged _cryptoProvider = new RijndaelManaged();

        private ICryptoTransform _decryptor;

        public RijndaelDecryptor() => _decryptor = _cryptoProvider.CreateDecryptor();

        public RijndaelDecryptor(byte[] key, byte[] iv) => _decryptor = _cryptoProvider.CreateDecryptor(key, iv);

        public override byte[] Decrypt(byte[] input)
        {
            using (var memoryStream = new MemoryStream(input))
            using (var cryptoStream = new CryptoStream(memoryStream, _decryptor, CryptoStreamMode.Read))
            using (var reader = new StreamReader(cryptoStream))
                return Encoding.UTF8.GetBytes(reader.ReadToEnd());
        }

        public void Dispose()
        {
            _cryptoProvider?.Dispose();
            _decryptor?.Dispose();
        }
    }
}