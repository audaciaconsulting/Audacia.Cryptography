using System;
using FluentAssertions;
using Xunit;

namespace Audacia.Cryptography.Tests
{
    public class Tests
    {
        [Fact]
        public void Rsa()
        {
            var bob = new RsaDecryptor();
            var alice = new RsaEncryptor(bob.PublicKey);
            
            var payload = Guid.NewGuid().ToString("N");
            var encrypted = alice.Encrypt(payload);
            encrypted.Should().NotBe(payload);

            var decrypted = bob.Decrypt(encrypted);
            decrypted.Should().Be(payload);
        }
    
        [Fact]
        public void Rijndael()
        {
            var bob = new RijndaelDecryptor();
            var alice = new RijndaelEncryptor(bob.Key, bob.Iv);
            
            var payload = Guid.NewGuid().ToString("N");
            var encrypted = alice.Encrypt(payload);
            encrypted.Should().NotBe(payload);

            var decrypted = bob.Decrypt(encrypted);
            decrypted.Should().Be(payload);
        }

        [Fact]
        public void Hybrid()
        {
            var bob = new HybridDecryptor();
            var alice = new HybridEncryptor(bob.PublicKey);
            
            var payload = Guid.NewGuid().ToString("N");
            var encrypted = alice.Encrypt(payload);
            encrypted.Should().NotBe(payload);

            var decrypted = bob.Decrypt(encrypted);
            decrypted.Should().Be(payload);
        }
    }
}
