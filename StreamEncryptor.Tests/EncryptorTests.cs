﻿using System;
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
        }

        private Encryptor<AesCryptoServiceProvider, HMACSHA256> GetEncryptor()
        {
            return new Encryptor<AesCryptoServiceProvider, HMACSHA256>(Constants.PASSWORD);
        }
    }
}
