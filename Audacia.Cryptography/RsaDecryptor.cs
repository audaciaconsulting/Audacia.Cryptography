using System;
using System.Security.Cryptography;

namespace Audacia.Cryptography
{
    public class RsaDecryptor : Decryptor, IDisposable
    {
        private RSACryptoServiceProvider _cryptoProvider = new RSACryptoServiceProvider { PersistKeyInCsp = false };
        
        public byte[] PublicKey => _cryptoProvider.ExportCspBlob(false);
        
        public byte[] PrivateKey => _cryptoProvider.ExportCspBlob(true);

        public RsaDecryptor() { }

        public RsaDecryptor(byte[] key) => _cryptoProvider.ImportCspBlob(key);

        public override byte[] Decrypt(byte[] input) => _cryptoProvider.Decrypt(input, true);

        public void Dispose() => _cryptoProvider?.Dispose();
    }
}   