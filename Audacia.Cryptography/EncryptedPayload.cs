namespace Audacia.Cryptography
{
    public class EncryptedPayload
    {
        public string Key { get; set; }

        public string Iv { get; set; }

        public string Payload { get; set; }
    }
}