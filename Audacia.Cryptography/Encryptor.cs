using System;
using System.Text;

namespace Audacia.Cryptography
{
    public abstract class Encryptor
    {
        public abstract byte[] Encrypt(byte[] input);

        public virtual string Encrypt(string input)
        {
            var bytes = Encoding.UTF8.GetBytes(input);
            var encrypted = Encrypt(bytes);
            return Convert.ToBase64String(encrypted);
        }
    }
}
