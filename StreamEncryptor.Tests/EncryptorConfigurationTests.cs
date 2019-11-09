using System.Security.Cryptography;
using Xunit;

namespace StreamEncryptor.Tests
{
    public class EncryptorConfigurationTests
    {
        [Fact]
        public void TestCtor()
        {
            EncryptorConfiguration configuration = new EncryptorConfiguration(
                EncryptorConfiguration.Default.Mode,
                EncryptorConfiguration.Default.Padding,
                EncryptorConfiguration.Default.KeySize,
                EncryptorConfiguration.Default.SaltSize,
                EncryptorConfiguration.Default.BufferSize);

            Assert.Equal(EncryptorConfiguration.Default.Mode, configuration.Mode);
            Assert.Equal(EncryptorConfiguration.Default.Padding, configuration.Padding);
            Assert.Equal(EncryptorConfiguration.Default.KeySize, configuration.KeySize);
            Assert.Equal(EncryptorConfiguration.Default.SaltSize, configuration.SaltSize);
            Assert.Equal(EncryptorConfiguration.Default.BufferSize, configuration.BufferSize);
        }

        [Fact]
        public void TestCheckConfiguration()
        {
            EncryptorConfiguration configuration = EncryptorConfiguration.Default;
            Assert.True(configuration.CheckConfigValid());

            configuration = new EncryptorConfiguration(CipherMode.CBC, PaddingMode.PKCS7, 0, 0, 0);
            Assert.False(configuration.CheckConfigValid());
        }

        [Fact]
        public void TestEquals()
        {
            EncryptorConfiguration config1 = EncryptorConfiguration.Default;
            EncryptorConfiguration config2 = EncryptorConfiguration.Default;
            EncryptorConfiguration config3 = new EncryptorConfiguration(CipherMode.ECB, PaddingMode.None, 0, 0, 0);

            Assert.False(config1.Equals(1));
            Assert.True(config1.Equals(config2));
            Assert.False(config1.Equals(config3));

            Assert.True(config1 == config2);
            Assert.False(config1 == config3);
            Assert.False(config1 != config2);
            Assert.True(config1 != config3);
        }

        [Fact]
        public void TestGetHashCode()
        {
            Assert.True(EncryptorConfiguration.Default.GetHashCode() != 0);
        }
    }
}
