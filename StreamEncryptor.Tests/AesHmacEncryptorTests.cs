using StreamEncryptor.Predefined;
using System.IO;
using Xunit;

namespace StreamEncryptor.Tests
{
    public class AesHmacEncryptorTests
    {
        private readonly byte[] RANDOM_BYTES = new byte[] { 80, 64, 1, 25, 97, 123, 0, 255 };
        private readonly string PASSWORD = "password";

        [Fact]
        public async void TestAuthenticatePeekTrue()
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
        public async void TestAuthenticatePeekFalse()
        {
            MemoryStream ms = new MemoryStream(RANDOM_BYTES);

            using (AesHmacEncryptor encryptor = new AesHmacEncryptor(PASSWORD))
            {
                MemoryStream encrypted = await encryptor.EncryptAsync<MemoryStream>(ms).ConfigureAwait(false);
                byte[] buffer = encrypted.GetBuffer();

                byte substitute = 0;
                do
                {
                    buffer[0] = substitute++;
                    substitute = substitute++;
                } while (buffer[0] == substitute);

                MemoryStream tampered = new MemoryStream(buffer);
                Assert.False(await encryptor.AuthenticateAsync(tampered).ConfigureAwait(false));
                Assert.True(tampered.Position == 0);
            }
        }

        [Fact]
        public async void TestAuthenticateNoPeekTrue()
        {
            MemoryStream ms = new MemoryStream(RANDOM_BYTES);

            using (AesHmacEncryptor encryptor = new AesHmacEncryptor(PASSWORD))
            {
                MemoryStream encrypted = await encryptor.EncryptAsync<MemoryStream>(ms).ConfigureAwait(false);

                var result = await encryptor.AuthenticateAsync(encrypted, false).ConfigureAwait(false);
                Assert.True(result.AuthenticationSuccess);
                Assert.True(encrypted.Position != 0);
            }
        }

        [Fact]
        public async void TestAuthenticateNoPeekFalse()
        {
            MemoryStream ms = new MemoryStream(RANDOM_BYTES);

            using (AesHmacEncryptor encryptor = new AesHmacEncryptor(PASSWORD))
            {
                MemoryStream encrypted = await encryptor.EncryptAsync<MemoryStream>(ms).ConfigureAwait(false);
                byte[] buffer = encrypted.GetBuffer();

                byte substitute = 0;
                do
                {
                    buffer[0] = substitute++;
                    substitute = substitute++;
                } while (buffer[0] == substitute);

                MemoryStream tampered = new MemoryStream(buffer);
                var result = await encryptor.AuthenticateAsync(tampered, false).ConfigureAwait(false);
                Assert.False(result.AuthenticationSuccess);
                Assert.True(tampered.Position != 0);
            }
        }
    }
}
