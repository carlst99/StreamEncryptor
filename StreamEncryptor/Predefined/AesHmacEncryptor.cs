using System.Security.Cryptography;

namespace StreamEncryptor.Predefined
{
    public class AesHmacEncryptor : Encryptor<AesCryptoServiceProvider, HMACSHA256>
    {
        public AesHmacEncryptor(string password)
            : base (password)
        {
        }

        public AesHmacEncryptor(string password, EncryptorConfiguration configuration)
            : base(password, configuration)
        {
        }
    }
}
