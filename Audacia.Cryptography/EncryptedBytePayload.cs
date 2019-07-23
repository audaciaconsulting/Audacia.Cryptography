using System;
using System.Linq;

namespace Audacia.Cryptography
{
    public class EncryptedBytePayload
    {
        public byte[] Payload { get; set; }
        public byte[]  Iv { get; set; }
        public byte[]  Key { get; set; }
        
        private const string Delimiter = "&";
        
        public override string ToString()
        {
            var base64Strings = new[]
                {
                    Key,
                    Iv,
                    Payload
                }
                .Select(Convert.ToBase64String);

            return string.Join(Delimiter, base64Strings);
        }
    }
}