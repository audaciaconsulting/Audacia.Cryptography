using System;
using FluentAssertions;
using Xunit;

namespace Audacia.Cryptography.Tests
{
    public class Tests
    {
        private Random Random { get; } = new Random();
        
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
        public void HybridString()
        {
            var bob = new HybridDecryptor();
            var alice = new HybridEncryptor(bob.PublicKey);
            
            var payload = Guid.NewGuid().ToString("N");
            var encrypted = alice.Encrypt(payload);
            encrypted.Should().NotBe(payload);

            var decrypted = bob.Decrypt(encrypted);
            decrypted.Should().Be(payload);
        }
        
        [Fact]
        public void HybridBytes()
        {
            var bob = new HybridDecryptor();
            var alice = new HybridEncryptor(bob.PublicKey);

            var payload = new byte[12];
            Random.NextBytes(payload);
            
            var encrypted = alice.Encrypt(payload);
            encrypted.Should().NotBeEquivalentTo(payload);

            var decrypted = bob.Decrypt(encrypted);
            decrypted.Should().AllBeEquivalentTo(payload);
        }

        [Fact]
        public void HybridParts()
        {
            var bob = new HybridDecryptor();
            var alice = new HybridEncryptor(bob.PublicKey);
            
            var payload = Guid.NewGuid().ToString("N");
            var encrypted = alice.Encrypt(payload);
            encrypted.Should().NotBe(payload);
            var parts = encrypted.LowMemorySplit('&');
            var decrypted = bob.Decrypt(parts[0], parts[1], parts[2]);
            decrypted.Should().Be(payload);
        }
        
    }
}
