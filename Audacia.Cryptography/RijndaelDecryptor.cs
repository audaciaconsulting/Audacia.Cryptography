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
            using (var memoryStream = new MemoryStream())
            using (var cryptoStream = new CryptoStream(memoryStream, _decryptor, CryptoStreamMode.Write))
            {
                cryptoStream.Write(input, 0, input.Length);
                cryptoStream.FlushFinalBlock();
                return memoryStream.ToArray();
            }
        }

        public void Dispose()
        {
            _cryptoProvider?.Dispose();
            _decryptor?.Dispose();
        }
    }
}