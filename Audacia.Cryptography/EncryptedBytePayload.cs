namespace Audacia.Cryptography
{
    public class EncryptedBytePayload
    {
        public byte[] Payload { get; set; }
        public byte[]  Iv { get; set; }
        public byte[]  Key { get; set; }
    }
}