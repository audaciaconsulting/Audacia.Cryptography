namespace Audacia.Cryptography
{
    public class EncryptedPayload
    {
        public string Key { get; set; } = string.Empty;

        public string Iv { get; set; } = string.Empty;

        public string Payload { get; set; } = string.Empty;
        
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