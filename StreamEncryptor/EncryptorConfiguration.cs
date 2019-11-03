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
            BufferSize = 40960
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

        public int GetSaltSizeInBits() => SaltSize * BIT_MULTIPLIER;

        /// <summary>
        /// Checks that this configuration is valid
        /// </summary>
        /// <returns></returns>
        public bool CheckConfigValid()
        {
            return BufferSize > 0
                && KeySize > 0
                && SaltSize > 0;
        }

        #region Equality Overrides

        public override bool Equals(object obj)
        {
            return obj is EncryptorConfiguration c
                && c.BufferSize.Equals(BufferSize)
                && c.KeySize.Equals(KeySize)
                && c.Mode.Equals(Mode)
                && c.Padding.Equals(Padding)
                && c.SaltSize.Equals(SaltSize);
        }

        public override int GetHashCode()
        {
            unchecked
            {
                int hash = 17;
                hash = (hash * 23) + BufferSize.GetHashCode();
                hash = (hash * 23) + KeySize.GetHashCode();
                hash = (hash * 23) + Mode.GetHashCode();
                hash = (hash * 23) + Padding.GetHashCode();
                hash = (hash * 23) + SaltSize.GetHashCode();
                return hash;
            }
        }

        public static bool operator ==(EncryptorConfiguration left, EncryptorConfiguration right)
        {
            return left.Equals(right);
        }

        public static bool operator !=(EncryptorConfiguration left, EncryptorConfiguration right)
        {
            return !(left == right);
        }

        #endregion
    }
}
