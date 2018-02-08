using System;
using System.Security.Cryptography;

namespace Audacia.Cryptography
{
    public class RsaEncryptor : Encryptor, IDisposable
    {
        private RSACryptoServiceProvider _cryptoProvider = new RSACryptoServiceProvider { PersistKeyInCsp = false };

        public byte[] PublicKey => _cryptoProvider.ExportCspBlob(false);
        
        public byte[] PrivateKey => _cryptoProvider.ExportCspBlob(true);

        public RsaEncryptor() { }

        public RsaEncryptor(byte[] key) => _cryptoProvider.ImportCspBlob(key);

        public override byte[] Encrypt(byte[] input) => _cryptoProvider.Encrypt(input, true);

        public void Dispose() => _cryptoProvider?.Dispose();
    }
}