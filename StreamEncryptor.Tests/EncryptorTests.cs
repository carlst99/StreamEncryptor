using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using StreamEncryptor.Exceptions;
using StreamEncryptor.Extensions;
using Xunit;

namespace StreamEncryptor.Tests
{
    public class EncryptorTests
    {
        [Fact]
        public void TestCtor()
        {
            Assert.Throws<ArgumentNullException>(() => new Encryptor<AesCryptoServiceProvider, HMACSHA256>(null));
            Assert.Throws<ArgumentNullException>(() => new Encryptor<AesCryptoServiceProvider, HMACSHA256>(string.Empty));

            // Just use defaults
            EncryptorConfiguration config = new EncryptorConfiguration(CipherMode.CBC, PaddingMode.None, 32, 16, 256);
            using (var encryptor = new Encryptor<AesCryptoServiceProvider, HMACSHA256>(Constants.PASSWORD, config))
                Assert.Equal(config, encryptor.Configuration);
        }

        [Fact]
        public async void TestDispose()
        {
            using (var encryptor = GetEncryptor())
            {
                encryptor.Dispose();
                Assert.Throws<ObjectDisposedException>(() => encryptor.CheckDisposed());
                await Assert.ThrowsAsync<ObjectDisposedException>(() =>
                    encryptor.DecryptAsync(Constants.GetRandomStream())).ConfigureAwait(false);
                await Assert.ThrowsAsync<ObjectDisposedException>(() =>
                    encryptor.EncryptAsync(Constants.GetRandomStream())).ConfigureAwait(false);
                await Assert.ThrowsAsync<ObjectDisposedException>(() =>
                    encryptor.AuthenticateAsync(Constants.GetRandomStream())).ConfigureAwait(false);
            }
        }

        [Fact]
        public async void TestDecrypt()
        {
            using (var encryptor = GetEncryptor())
            {
                await Assert.ThrowsAsync<ArgumentNullException>(() => encryptor.EncryptAsync(null)).ConfigureAwait(false);

                MemoryStream decryptedStream = await encryptor.DecryptAsync(await Constants.GetEncryptedStream().ConfigureAwait(false)).ConfigureAwait(false);
                Assert.False(decryptedStream.IsNullOrEmpty());
            }
        }

        [Fact]
        public async void TestInvalidDecrypt()
        {
            using (var encryptor = GetEncryptor())
            {
                await Assert.ThrowsAsync<EncryptionException>(() => encryptor.DecryptAsync(Constants.GetRandomStream())).ConfigureAwait(false);
            }
        }

        [Fact]
        public async void TestEncrypt()
        {
            using (var encryptor = GetEncryptor())
            {
                await Assert.ThrowsAsync<ArgumentNullException>(() => encryptor.DecryptAsync(null)).ConfigureAwait(false);

                MemoryStream encryptedStream = await encryptor.EncryptAsync(Constants.GetRandomStream()).ConfigureAwait(false);
                Assert.False(encryptedStream.IsNullOrEmpty());
            }
        }

        [Fact]
        public async void TestRoundTrip()
        {
            using (var encryptor = GetEncryptor())
            {
                MemoryStream encryptedStream = await encryptor.EncryptAsync(Constants.GetRandomStream()).ConfigureAwait(false);
                encryptedStream = await encryptor.DecryptAsync(encryptedStream).ConfigureAwait(false);

                Assert.Equal(Constants.RANDOM_BYTES, encryptedStream.GetBuffer().Take(Constants.RANDOM_BYTES.Length));
            }
        }

        [Fact]
        public async void TestSetPassword()
        {
            using (var encryptor = GetEncryptor())
            {
                MemoryStream ms = await Constants.GetEncryptedStream();
                encryptor.SetPassword(Constants.PASSWORD.Reverse().ToString());
                Assert.False(await encryptor.AuthenticateAsync(ms));
            }
        }

        private Encryptor<AesCryptoServiceProvider, HMACSHA256> GetEncryptor()
        {
            return new Encryptor<AesCryptoServiceProvider, HMACSHA256>(Constants.PASSWORD);
        }
    }
}
