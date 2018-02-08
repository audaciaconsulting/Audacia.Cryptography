using System;
using System.Diagnostics;
using System.Text;

namespace Audacia.Cryptography
{
    public class HybridDecryptor : Decryptor, IDisposable
    {
        private const string Delimiter = "&";
        private RsaDecryptor _rsa;

        public byte[] PublicKey => _rsa.PublicKey;
        
        public byte[] PrivateKey => _rsa.PrivateKey;

        public HybridDecryptor() => _rsa = new RsaDecryptor();

        public HybridDecryptor(byte[] key) => _rsa = new RsaDecryptor(key);

        public override byte[] Decrypt(byte[] input)
        {
            var @string = Encoding.UTF8.GetString(input);
            var decrypted = Decrypt(@string);
            return Encoding.UTF8.GetBytes(decrypted);
        }

        public override string Decrypt(string input)
        {
            var parts = input.Split(new[] { Delimiter }, StringSplitOptions.None);
            if (parts.Length != 3) throw new FormatException($"{nameof(input)} was not in the correct format");

            var encryptedKey = Convert.FromBase64String(parts[0]);
            var encryptedIv = Convert.FromBase64String(parts[1]);
            var payloadBytes = Convert.FromBase64String(parts[2]);
            var key = _rsa.Decrypt(encryptedKey);
            var iv = _rsa.Decrypt(encryptedIv);

            using (var rijndael = new RijndaelDecryptor(key, iv))
            {
                var bytes = rijndael.Decrypt(payloadBytes);
                return Encoding.UTF8.GetString(bytes);
            }
        }

        public void Dispose()
        {
            _rsa?.Dispose();
        }
    }
}