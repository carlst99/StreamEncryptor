using StreamEncryptor.Predefined;
using System;
using System.IO;
using System.Threading.Tasks;
using Xunit;

namespace StreamEncryptor.Tests
{
    public class EncryptorAuthenticationTests
    {
        [Fact]
        public async void TestAuthenticateValid()
        {
            MemoryStream ms = new MemoryStream(Constants.RANDOM_BYTES);

            using (AesHmacEncryptor encryptor = new AesHmacEncryptor(Constants.PASSWORD))
            {
                MemoryStream encrypted = await encryptor.EncryptAsync<MemoryStream>(ms).ConfigureAwait(false);
                Assert.True(await encryptor.AuthenticateAsync(encrypted).ConfigureAwait(false));
                Assert.True(encrypted.Position == 0);
            }
        }

        [Fact]
        public async void TestAuthenticateInvalid()
        {
            using (AesHmacEncryptor encryptor = new AesHmacEncryptor(Constants.PASSWORD))
            {
                MemoryStream tampered = await GetTamperedStream(encryptor).ConfigureAwait(false);
                Assert.False(await encryptor.AuthenticateAsync(tampered).ConfigureAwait(false));
                Assert.True(tampered.Position == 0);
            }
        }

        [Fact]
        public async void TestAuthenticateInternalValid()
        {
            MemoryStream ms = new MemoryStream(Constants.RANDOM_BYTES);

            using (AesHmacEncryptor encryptor = new AesHmacEncryptor(Constants.PASSWORD))
            {
                MemoryStream encrypted = await encryptor.EncryptAsync<MemoryStream>(ms).ConfigureAwait(false);

                var result = await encryptor.AuthenticateAsync(encrypted, false).ConfigureAwait(false);
                Assert.NotNull(result.Buffer);
                Assert.True(result.AuthenticationSuccess);
                Assert.True(encrypted.Position != 0);
            }
        }

        [Fact]
        public async void TestAuthenticateInternalInvalid()
        {
            using (AesHmacEncryptor encryptor = new AesHmacEncryptor(Constants.PASSWORD))
            {
                MemoryStream tampered = await GetTamperedStream(encryptor).ConfigureAwait(false);
                var result = await encryptor.AuthenticateAsync(tampered, false).ConfigureAwait(false);
                Assert.False(result.AuthenticationSuccess);
            }
        }

        [Fact]
        public async void TestAuthenticateInternalPeek()
        {
            MemoryStream ms = new MemoryStream(Constants.RANDOM_BYTES);

            using (AesHmacEncryptor encryptor = new AesHmacEncryptor(Constants.PASSWORD))
            {
                MemoryStream encrypted = await encryptor.EncryptAsync<MemoryStream>(ms).ConfigureAwait(false);

                var result = await encryptor.AuthenticateAsync(encrypted, true).ConfigureAwait(false);
                Assert.Null(result.Buffer);
            }
        }

        [Fact]
        public void TestArgChecks()
        {
            using (AesHmacEncryptor encryptor = new AesHmacEncryptor(Constants.PASSWORD))
            {
                Assert.ThrowsAsync<ArgumentNullException>(() => encryptor.AuthenticateAsync<MemoryStream>(null));
                Assert.ThrowsAsync<ArgumentNullException>(() => encryptor.AuthenticateAsync(new MemoryStream()));
            }
        }

        private async Task<MemoryStream> GetTamperedStream(IEncryptor encryptor)
        {
            MemoryStream ms = new MemoryStream(Constants.RANDOM_BYTES);
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
