using System;
using System.Linq;
using System.Text;

namespace Audacia.Cryptography
{
    public class HybridEncryptor : Encryptor, IDisposable
    {
        private RsaEncryptor _rsa;
        private RijndaelEncryptor _rijndael = new RijndaelEncryptor();

        public byte[] PublicKey => _rsa.PublicKey;
        
        public byte[] PrivateKey => _rsa.PrivateKey;

        public HybridEncryptor() => _rsa = new RsaEncryptor();

        public HybridEncryptor(byte[] key) => _rsa = new RsaEncryptor(key);

        public override byte[] Encrypt(byte[] input)
        {
            var result = EncryptInternal(input);
            return Encoding.UTF8.GetBytes(result);
        }

        public override string Encrypt(string input)
        {
            var bytes = Encoding.UTF8.GetBytes(input);
            return EncryptInternal(bytes);
        }

        private string EncryptInternal(byte[] input) => EncryptAsBytePayload(input).ToString();

        public EncryptedPayload EncryptAsPayload(string input) =>
            new EncryptedPayload
            {
                Key = Convert.ToBase64String(_rsa.Encrypt(_rijndael.Key)),
                Iv = Convert.ToBase64String(_rsa.Encrypt(_rijndael.Iv)),
                Payload = _rijndael.Encrypt(input)
            };

        public EncryptedBytePayload EncryptAsBytePayload(byte[] input) =>
            new EncryptedBytePayload
            {
                Key = _rsa.Encrypt(_rijndael.Key),
                Iv = _rsa.Encrypt(_rijndael.Iv),
                Payload = _rijndael.Encrypt(input)
            };

        public void Dispose()
        {
            _rsa?.Dispose();
            _rijndael?.Dispose();
        }
    }
}