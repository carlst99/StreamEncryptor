﻿using Xunit;

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
    }
}