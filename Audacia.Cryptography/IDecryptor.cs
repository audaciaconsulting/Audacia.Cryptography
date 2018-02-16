namespace Audacia.Cryptography
{
    public interface IDecryptor
    {
        byte[] Decrypt(byte[] input);

        string Decrypt(string input);
    }
}