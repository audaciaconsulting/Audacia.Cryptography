using System;
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
            => Encoding.UTF8.GetBytes(EncryptAsBytePayload(input).ToString());

        public override string Encrypt(string input) => EncryptAsPayload(input).ToString();

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