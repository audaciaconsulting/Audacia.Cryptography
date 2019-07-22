using System;
using System.Diagnostics;
using System.Linq;
using System.Text;

namespace Audacia.Cryptography
{
    public class HybridDecryptor : Decryptor, IDisposable
    {
        private const char Delimiter = '&';
        private RsaDecryptor _rsa;

        public byte[] PublicKey => _rsa.PublicKey;
        
        public byte[] PrivateKey => _rsa.PrivateKey;

        public HybridDecryptor() => _rsa = new RsaDecryptor();

        public HybridDecryptor(byte[] key) => _rsa = new RsaDecryptor(key);

        public override byte[] Decrypt(byte[] input)
        {
            var @string = Encoding.UTF8.GetString(input);
            return DecryptInternal(@string);
        }

        public override string Decrypt(string input)
        {
            var bytes = DecryptInternal(input);
            return Encoding.UTF8.GetString(bytes);
        }

        private byte[] DecryptInternal(string input)
        {
            var parts = input.LowMemorySplit(Delimiter);
            
            if (parts.Length != 3) throw new FormatException($"{nameof(input)} was not in the correct format");

            var encryptedKey = Convert.FromBase64String(parts[0]);
            var encryptedIv = Convert.FromBase64String(parts[1]);
            var payloadBytes = Convert.FromBase64String(parts[2]);
            var key = _rsa.Decrypt(encryptedKey);
            var iv = _rsa.Decrypt(encryptedIv);

            using (var rijndael = new RijndaelDecryptor(key, iv))
                return rijndael.Decrypt(payloadBytes);
        }

        public string Decrypt(string keyStr, string ivStr, string payload)
        {
            var encryptedKey = Convert.FromBase64String(keyStr);
            var encryptedIv = Convert.FromBase64String(ivStr);
            var payloadBytes = Convert.FromBase64String(payload);
            var key = _rsa.Decrypt(encryptedKey);
            var iv = _rsa.Decrypt(encryptedIv);

            using (var rijndael = new RijndaelDecryptor(key, iv))
                return Encoding.UTF8.GetString(rijndael.Decrypt(payloadBytes));
        }

        public void Dispose()
        {
            _rsa?.Dispose();
        }
    }
}