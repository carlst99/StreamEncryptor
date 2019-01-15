using System;
using System.Collections.Generic;
using System.Text;

namespace StreamEncryptor.Tests
{
    public static class Constants
    {
        public const int SALT_SIZE = 16;
        public const int KEY_SIZE = 32;
        public const string PASSWORD = "password";
        public static readonly byte[] RANDOM_BYTES = new byte[] { 80, 64, 1, 25, 97, 123, 0, 255 };
    }
}
