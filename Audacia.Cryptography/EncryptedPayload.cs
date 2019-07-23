namespace Audacia.Cryptography
{
    public class EncryptedPayload
    {
        public string Key { get; set; }

        public string Iv { get; set; }

        public string Payload { get; set; }
        
        public override string ToString()
        {
            var base64Strings = new[]
            {
                Key,
                Iv,
                Payload
            };

            return string.Join(PayloadConstants.Delimiter, base64Strings);
        }
    }
}