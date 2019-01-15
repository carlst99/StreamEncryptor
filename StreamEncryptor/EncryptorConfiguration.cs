using System.Security.Cryptography;

namespace StreamEncryptor
{
    public struct EncryptorConfiguration
    {
        internal const int BIT_MULTIPLIER = 8;

        public static readonly EncryptorConfiguration Default = new EncryptorConfiguration()
        {
            Mode = CipherMode.CBC,
            Padding = PaddingMode.PKCS7,
            KeySize = 32,
            SaltSize = 16,
            BufferSize = 256
        };

        /// <summary>
        /// The <see cref="CipherMode"/> that should be used during encryption
        /// </summary>
        public CipherMode Mode { get; private set; }

        /// <summary>
        /// The <see cref="PaddingMode"/> that should be used during encryption
        /// </summary>
        public PaddingMode Padding { get; private set; }

        /// <summary>
        /// The length in bytes of the key that should be generated when deriving a string password
        /// </summary>
        public int KeySize { get; private set; }

        /// <summary>
        /// The length in bytes of any generated salts/IVs
        /// </summary>
        public int SaltSize { get; private set; }

        /// <summary>
        /// The length in bytes of any buffers created during read and write operations
        /// </summary>
        public int BufferSize { get; private set; }

        public EncryptorConfiguration(CipherMode mode, PaddingMode padding, int keySize, int saltSize, int bufferSize)
        {
            Mode = mode;
            Padding = padding;
            KeySize = keySize;
            SaltSize = saltSize;
            BufferSize = bufferSize;
        }

        public int GetKeySizeInBits() => KeySize * BIT_MULTIPLIER;
    }
}
