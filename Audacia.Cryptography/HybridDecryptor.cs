using System;
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
            return DecryptFromString(@string);
        }

        public override string Decrypt(string input)
        {
            var bytes = DecryptFromString(input);
            return Encoding.UTF8.GetString(bytes);
        }

        private byte[] DecryptFromString(string input)
        {
            var parts = input.LowMemorySplit(Delimiter);

            if (parts.Length != 3) throw new FormatException($"{nameof(input)} was not in the correct format");

            return DecryptInternal(parts[0], parts[1],parts[2]);
        }

        private byte[] DecryptInternal(string keyStr, string ivStr, string payloadStr) 
        => DecryptInternal(Convert.FromBase64String(keyStr), Convert.FromBase64String(ivStr),
            Convert.FromBase64String(payloadStr));
        
        private byte[] DecryptInternal(byte[] key, byte[] iv, byte[] payload)
        {
            using (var rijndael = new RijndaelDecryptor(_rsa.Decrypt(key), _rsa.Decrypt(iv)))
                return rijndael.Decrypt(payload);
        }

        public string Decrypt(EncryptedPayload payload)
            => Encoding.UTF8.GetString(DecryptInternal(payload.Key, payload.Iv, payload.Payload));

        public byte[] Decrypt(EncryptedBytePayload payload)
            => DecryptInternal(payload.Key, payload.Iv, payload.Payload);

        public void Dispose()
        {
            _rsa?.Dispose();
        }
    }
}