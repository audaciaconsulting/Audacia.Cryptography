using System;
using Shouldly;
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
            encrypted.ShouldNotBe(payload);

            var decrypted = bob.Decrypt(encrypted);
            decrypted.ShouldBe(payload);
        }
    
        [Fact]
        public void Rijndael()
        {    
            var bob = new RijndaelDecryptor();
            var alice = new RijndaelEncryptor(bob.Key, bob.Iv);
            
            var payload = Guid.NewGuid().ToString("N");
            var encrypted = alice.Encrypt(payload);
            encrypted.ShouldNotBe(payload);

            var decrypted = bob.Decrypt(encrypted);
            decrypted.ShouldBe(payload);
        }

        [Fact]
        public void HybridString()
        {
            var bob = new HybridDecryptor();
            var alice = new HybridEncryptor(bob.PublicKey);
            
            var payload = Guid.NewGuid().ToString("N");
            var encrypted = alice.Encrypt(payload);
            encrypted.ShouldNotBe(payload);

            var decrypted = bob.Decrypt(encrypted);
            decrypted.ShouldBe(payload);
        }
		
        
        [Fact]
        public void HybridBytes()
        {
            var bob = new HybridDecryptor();
            var alice = new HybridEncryptor(bob.PublicKey);
            var payload = new byte[12];
            Random.NextBytes(payload);
            
            var encrypted = alice.Encrypt(payload);
            encrypted.ShouldNotBe(payload);
            var decrypted = bob.Decrypt(encrypted);
            decrypted.ShouldBeEquivalentTo(payload);
        }
        
        [Fact]
        public void HybridPayload()
        {
            var bob = new HybridDecryptor();
            var alice = new HybridEncryptor(bob.PublicKey);
            
            var payload = Guid.NewGuid().ToString("N");
            var encrypted = alice.EncryptAsPayload(payload);
            encrypted.Payload.ShouldNotBe(payload);
            
            var decrypted = bob.Decrypt(encrypted);
            decrypted.ShouldBe(payload);
        }

        [Fact]
        public void HybridBytespayload()
        {
            var bob = new HybridDecryptor();
            var alice = new HybridEncryptor(bob.PublicKey);

            var payload = new byte[12];
            Random.NextBytes(payload);

            var encrypted = alice.EncryptAsBytePayload(payload);

            var decrypted = bob.Decrypt(encrypted);

            decrypted.ShouldBeEquivalentTo(payload);
        }
        
    }
}
