using System;
using System.Linq;

namespace Audacia.Cryptography
{
    public class EncryptedBytePayload
    {
        public byte[] Payload { get; set; } = null!;
        public byte[] Iv { get; set; } = null!;
        public byte[] Key { get; set; } = null!;

        public override string ToString()
        {
            var base64Strings = new[]
                {
                    Key,
                    Iv,
                    Payload
                }
                .Select(Convert.ToBase64String);

            return string.Join(PayloadConstants.Delimiter, base64Strings);
        }
    }
}