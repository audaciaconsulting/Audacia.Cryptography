using System;
using System.Text;

namespace Audacia.Cryptography
{
    public abstract class Decryptor : IDecryptor
    {
        public abstract byte[] Decrypt(byte[] input);

        public virtual string Decrypt(string input)
        {
            var bytes = Convert.FromBase64String(input);
            var decrypted = Decrypt(bytes);
            return Encoding.UTF8.GetString(decrypted);
        }
    }
}