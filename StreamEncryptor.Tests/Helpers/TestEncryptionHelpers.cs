using StreamEncryptor.Helpers;
using System;
using Xunit;

namespace StreamEncryptor.Tests.Helpers
{
    public class TestEncryptionHelpers
    {
        [Fact]
        public void TestDeriveKey()
        {
            Assert.Throws<ArgumentNullException>(() => EncryptionHelpers.DeriveKey(null,
                new byte[Constants.SALT_SIZE],
                Constants.KEY_SIZE));

            Assert.Throws<ArgumentNullException>(() => EncryptionHelpers.DeriveKey(string.Empty,
                new byte[Constants.SALT_SIZE],
                Constants.KEY_SIZE));

            Assert.Throws<ArgumentNullException>(() => EncryptionHelpers.DeriveKey(Constants.PASSWORD,
                null,
                Constants.KEY_SIZE));

            Assert.Throws<ArgumentNullException>(() => EncryptionHelpers.DeriveKey(Constants.PASSWORD,
                new byte[0],
                Constants.KEY_SIZE));

            Assert.Throws<ArgumentException>(() => EncryptionHelpers.DeriveKey(Constants.PASSWORD,
                new byte[Constants.SALT_SIZE],
                0));

            byte[] salt = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };
            Assert.Equal(EncryptionHelpers.DeriveKey("test", salt, 32), EncryptionHelpers.DeriveKey("test", salt, 32));
        }

        [Fact]
        public void TestGenerateRandomIV()
        {
            Assert.Throws<ArgumentException>(() => EncryptionHelpers.GenerateRandomIV(0));
            Assert.NotEmpty(EncryptionHelpers.GenerateRandomIV(8));
            Assert.NotEqual(EncryptionHelpers.GenerateRandomIV(8), EncryptionHelpers.GenerateRandomIV(8));
        }
    }
}
