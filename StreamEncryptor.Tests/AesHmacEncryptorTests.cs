using System;
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
            }
        }
    }
}
