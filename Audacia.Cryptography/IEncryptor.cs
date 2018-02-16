namespace Audacia.Cryptography
{
    public interface IEncryptor
    {
        byte[] Encrypt(byte[] input);

        string Encrypt(string input);
    }
}