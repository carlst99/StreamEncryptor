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
        }

        [Fact]
        public void TestGenerateRandomIV()
        {
            Assert.Throws<ArgumentException>(() => EncryptionHelpers.GenerateRandomIV(0));
        }
    }
}
