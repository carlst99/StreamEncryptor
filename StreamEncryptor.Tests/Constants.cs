using System.IO;
using System.Security.Cryptography;
using System.Threading.Tasks;

namespace StreamEncryptor.Tests
{
    public static class Constants
    {
        public const int SALT_SIZE = 16;
        public const int KEY_SIZE = 32;
        public const string PASSWORD = "password";
        public static readonly byte[] RANDOM_BYTES = new byte[] { 80, 64, 1, 25, 97, 123, 0, 255 };

        public static MemoryStream GetRandomStream() => new MemoryStream(RANDOM_BYTES, 0, RANDOM_BYTES.Length, true, true);

        public static async Task<MemoryStream> GetEncryptedStream<TAlgorithm, TAuthenticator>() where TAlgorithm : SymmetricAlgorithm, new() where TAuthenticator : HMAC, new()
        {
            using (Encryptor<TAlgorithm, TAuthenticator> encryptor = new Encryptor<TAlgorithm, TAuthenticator>(PASSWORD))
            {
                return await encryptor.EncryptAsync(GetRandomStream()).ConfigureAwait(false);
            }
        }

        public static async Task<MemoryStream> GetEncryptedStream() => await GetEncryptedStream<AesCryptoServiceProvider, HMACSHA256>().ConfigureAwait(false);
    }
}
