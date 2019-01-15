﻿using StreamEncryptor.Helpers;
using StreamEncryptor.Predefined;
using System;
using System.IO;
using System.Threading.Tasks;
using Xunit;

namespace StreamEncryptor.Tests
{
    public class EncryptorAuthenticationTests
    {
        private readonly byte[] RANDOM_BYTES = new byte[] { 80, 64, 1, 25, 97, 123, 0, 255 };
        private readonly string PASSWORD = "password";

        [Fact]
        public async void TestAuthenticateValid()
        {
            MemoryStream ms = new MemoryStream(RANDOM_BYTES);

            using (AesHmacEncryptor encryptor = new AesHmacEncryptor(PASSWORD))
            {
                MemoryStream encrypted = await encryptor.EncryptAsync<MemoryStream>(ms).ConfigureAwait(false);
                Assert.True(await encryptor.AuthenticateAsync(encrypted).ConfigureAwait(false));
                Assert.True(encrypted.Position == 0);
            }
        }

        [Fact]
        public async void TestAuthenticateInvalid()
        {
            MemoryStream ms = new MemoryStream(RANDOM_BYTES);

            using (AesHmacEncryptor encryptor = new AesHmacEncryptor(PASSWORD))
            {
                MemoryStream tampered = await GetTamperedStream(encryptor).ConfigureAwait(false);
                Assert.False(await encryptor.AuthenticateAsync(tampered).ConfigureAwait(false));
                Assert.True(tampered.Position == 0);
            }
        }

        [Fact]
        public async void TestAuthenticateInternalValid()
        {
            MemoryStream ms = new MemoryStream(RANDOM_BYTES);

            using (AesHmacEncryptor encryptor = new AesHmacEncryptor(PASSWORD))
            {
                MemoryStream encrypted = await encryptor.EncryptAsync<MemoryStream>(ms).ConfigureAwait(false);

                var result = await encryptor.AuthenticateAsync(encrypted, false).ConfigureAwait(false);
                Assert.NotNull(result.RemainingStream);
                Assert.True(result.AuthenticationSuccess);
                Assert.True(encrypted.Position != 0);
            }
        }

        [Fact]
        public async void TestAuthenticateInternalInvalid()
        {
            using (AesHmacEncryptor encryptor = new AesHmacEncryptor(PASSWORD))
            {
                MemoryStream tampered = await GetTamperedStream(encryptor).ConfigureAwait(false);
                var result = await encryptor.AuthenticateAsync(tampered, false).ConfigureAwait(false);
                Assert.False(result.AuthenticationSuccess);
            }
        }

        [Fact]
        public async void TestAuthenticateInternalPeek()
        {
            MemoryStream ms = new MemoryStream(RANDOM_BYTES);

            using (AesHmacEncryptor encryptor = new AesHmacEncryptor(PASSWORD))
            {
                MemoryStream encrypted = await encryptor.EncryptAsync<MemoryStream>(ms).ConfigureAwait(false);

                var result = await encryptor.AuthenticateAsync(encrypted, true).ConfigureAwait(false);
                Assert.Null(result.RemainingStream);
            }
        }

        [Fact]
        public void TestArgChecks()
        {
            using (AesHmacEncryptor encryptor = new AesHmacEncryptor(PASSWORD))
            {
                Assert.ThrowsAsync<ArgumentNullException>(() => encryptor.AuthenticateAsync<MemoryStream>(null));
                Assert.ThrowsAsync<ArgumentNullException>(() => encryptor.AuthenticateAsync(new MemoryStream()));
            }
        }



        private async Task<MemoryStream> GetTamperedStream(IEncryptor encryptor)
        {
            MemoryStream ms = new MemoryStream(RANDOM_BYTES);
            MemoryStream encrypted = await encryptor.EncryptAsync<MemoryStream>(ms).ConfigureAwait(false);
            byte[] buffer = encrypted.GetBuffer();

            byte substitute = 0;
            do
            {
                buffer[0] = substitute++;
                substitute = substitute++;
            } while (buffer[0] == substitute);

            return new MemoryStream(buffer);
        }
    }
}