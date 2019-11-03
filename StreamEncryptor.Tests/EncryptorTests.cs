using StreamEncryptor.Exceptions;
using StreamEncryptor.Extensions;
using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
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
                await Assert.ThrowsAsync<ArgumentNullException>(() => encryptor.DecryptAsync(null)).ConfigureAwait(false);

                MemoryStream encryptedStream = await Constants.GetEncryptedStream().ConfigureAwait(false);
                MemoryStream decryptedStream = await encryptor.DecryptAsync(encryptedStream).ConfigureAwait(false);
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
            MemoryStream encryptedStream;
            using (var encryptor = GetEncryptor())
                encryptedStream = await encryptor.EncryptAsync(Constants.GetRandomStream()).ConfigureAwait(false);

            using (var encryptor = GetEncryptor())
            {
                encryptedStream = await encryptor.DecryptAsync(encryptedStream).ConfigureAwait(false);
                Assert.Equal(Constants.RANDOM_BYTES, GetStreamData(encryptedStream));
            }
        }

        [Fact]
        public async void TestSetPassword()
        {
            using (var encryptor = GetEncryptor())
            {
                Assert.Throws<ArgumentNullException>(() => encryptor.SetPassword(null));
                Assert.Throws<ArgumentNullException>(() => encryptor.SetPassword(string.Empty));

                MemoryStream ms = await Constants.GetEncryptedStream().ConfigureAwait(false);
                encryptor.SetPassword(Constants.PASSWORD.Reverse().ToString());
                Assert.False(await encryptor.AuthenticateAsync(ms).ConfigureAwait(false));

                encryptor.SetPassword(Constants.PASSWORD);
                Assert.True(await encryptor.AuthenticateAsync(ms).ConfigureAwait(false));
            }
        }

        [Fact]
        public async void TestRoundTripOnFile()
        {
            using (var encryptor = GetEncryptor())
            using (FileStream fs = new FileStream("TestFile.png", FileMode.Open, FileAccess.Read))
            {
                MemoryStream encryptedStream = await encryptor.EncryptAsync(fs).ConfigureAwait(false);
                encryptedStream = await encryptor.DecryptAsync(encryptedStream).ConfigureAwait(false);

                fs.Position = 0;
                Assert.Equal(GetStreamData(fs), GetStreamData(encryptedStream));
            }
        }

        private Encryptor<AesCryptoServiceProvider, HMACSHA256> GetEncryptor()
        {
            return new Encryptor<AesCryptoServiceProvider, HMACSHA256>(Constants.PASSWORD);
        }

        private byte[] GetStreamData(Stream stream)
        {
            byte[] data = new byte[stream.Length];
            stream.Read(data);
            return data;
        }
    }
}
