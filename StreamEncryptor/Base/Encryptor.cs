using StreamEncryptor.Exceptions;
using System;
using System.IO;
using System.Security.Cryptography;
using System.Threading.Tasks;

namespace StreamEncryptor.Base
{
    public abstract class Encryptor : IEncryptor
    {
        #region Constants

        /// <summary>
        /// The size of any keys
        /// </summary>
        public const int KEY_SIZE = 32;

        /// <summary>
        /// The size of any generated salts
        /// </summary>
        public const int SALT_SIZE = 16;

        /// <summary>
        /// The length of any buffers created during encryption/decryption
        /// </summary>
        internal const int BUFFER_READ_LENGTH = 256;

        #endregion

        #region Fields

        /// <summary>
        /// The algorithm used for encryption and decryption
        /// </summary>
        protected SymmetricAlgorithm _encryptor;

        /// <summary>
        /// The algorithm used to authenticate the data
        /// </summary>
        protected HMAC _authenticator;

        /// <summary>
        /// The user password
        /// </summary>
        protected string _password;

        #endregion

        /// <summary>
        /// Provides the base implementation for an encryption-authentication encryptor service
        /// </summary>
        /// <param name="password">The password to use for encryption</param>
        protected Encryptor(string password)
        {
            if (string.IsNullOrEmpty(password))
                throw new ArgumentNullException("Key required!");

            _password = password;
        }

        #region Decrypt

        /// <summary>
        /// When overriden in a derived class, decrypts a stream
        /// </summary>
        /// <typeparam name="T">The type of stream to decrypt to</typeparam>
        /// <param name="stream">The stream to decrypt</param>
        /// <returns></returns>
        public virtual Task<T> Decrypt<T>(Stream stream) where T : Stream, new()
        {
            CheckDisposed();
            return Task.FromResult(default(T));
        }

        /// <summary>
        /// When overriden in a derived class, decrypts a stream
        /// </summary>
        /// <param name="stream">The stream to decrypt</param>
        /// <returns>A <see cref="MemoryStream"/> containing the decrypted data</returns>
        public virtual Task<MemoryStream> Decrypt(Stream stream) => Decrypt<MemoryStream>(stream);

        #endregion

        #region Encrypt

        /// <summary>
        /// When overriden in a derived class, encrypts a stream
        /// </summary>
        /// <typeparam name="T">The type of stream to encrypt to</typeparam>
        /// <param name="stream">The stream to encrypt</param>
        /// <returns></returns>
        public virtual Task<T> Encrypt<T>(Stream stream) where T : Stream, new()
        {
            CheckDisposed();
            return Task.FromResult(default(T));
        }

        /// <summary>
        /// When overriden in a derived class, encrypts a stream
        /// </summary>
        /// <param name="stream">The stream to encrypt</param>
        /// <returns>A <see cref="MemoryStream"/> containing the encrypted data</returns>
        public virtual Task<MemoryStream> Encrypt(Stream stream) => Encrypt<MemoryStream>(stream);

        #endregion

        /// <summary>
        /// Authenticates an encrypted stream
        /// </summary>
        /// <typeparam name="T">The type of stream</typeparam>
        /// <param name="stream">An encrypted stream</param>
        /// <param name="seek">Whether or not to seek through the stream when authenticating</param>
        /// <returns></returns>
        protected virtual Task<bool> Authenticate<T>(T stream, bool seek) where T : Stream
        {
            CheckDisposed();
            return Task.FromResult(false);
        }

        /// <summary>
        /// Authenticates an encrypted stream
        /// </summary>
        /// <typeparam name="T">The type of stream</typeparam>
        /// <param name="stream">An encrypted stream</param>
        /// <returns></returns>
        public Task<bool> Authenticate<T>(T stream) where T : Stream
            => Authenticate(stream, true);

        /// <summary>
        /// Turns a string into a cryptographically-secure byte[] array
        /// </summary>
        /// <returns>A <see cref="byte"/> array containing the derived key</returns>
        public static byte[] DeriveKey(string key, byte[] salt)
        {
            if (string.IsNullOrEmpty(key))
                throw new ArgumentNullException("key may not be null or empty");

            try
            {
                using (Rfc2898DeriveBytes deriver = new Rfc2898DeriveBytes(key, salt))
                {
                    return deriver.GetBytes(KEY_SIZE);
                }
            }
            catch (Exception ex)
            {
                throw new EncryptionException("Error deriving key", ex)
                {
                    Error = EncryptionError.DeriveKeyError
                };
            }
        }

        /// <summary>
        /// Generates a random IV of length <see cref="SALT_SIZE"/>
        /// </summary>
        /// <returns>A <see cref="byte"/> array of length <see cref="SALT_SIZE"/> containing a randomly generated, cryptographically secure IV
        public static byte[] GenerateRandomIV()
        {
            byte[] iv = new byte[SALT_SIZE];
            try
            {
                using (RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider())
                    rng.GetBytes(iv);
            }
            catch (CryptographicException ex)
            {
                throw new EncryptionException("Error generating IV", ex)
                {
                    Error = EncryptionError.GenerateIVError
                };
            }
            return iv;
        }

        #region IDisposable Support

        private bool disposedValue = false;

        protected virtual void Dispose(bool disposing)
        {
            if (!disposedValue)
            {
                if (disposing)
                {
                    _encryptor?.Dispose();
                    _authenticator.Dispose();
                    _password = null;
                }

                disposedValue = true;
            }
        }

        public void Dispose()
        {
            Dispose(true);
        }

        protected void CheckDisposed()
        {
            if (disposedValue)
                throw new ObjectDisposedException(GetType().Name);
        }

        #endregion
    }
}
