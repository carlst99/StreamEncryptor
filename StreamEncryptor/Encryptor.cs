using StreamEncryptor.Exceptions;
using StreamEncryptor.Extensions;
using StreamEncryptor.Helpers;
using System;
#if DEBUG_DUMP
using System.Diagnostics;
#endif
using System.IO;
using System.Security.Cryptography;
using System.Threading.Tasks;

namespace StreamEncryptor
{
    public class Encryptor<TAlgorithm, TAuthenticator> : IEncryptor
        where TAlgorithm : SymmetricAlgorithm, new()
        where TAuthenticator : HMAC, new()
    {
        #region Constants

        /// <summary>
        /// The size, in bytes, allocated to output streams for storing the length of the payload
        /// </summary>
        public const int LENGTH_ALLOCATION_SIZE = sizeof(long);

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

        #region Properties

        /// <summary>
        /// The configuration used to setup this <see cref="Encryptor{TAlgorithm, TAuthenticator}"/> instance
        /// </summary>
        public EncryptorConfiguration Configuration;

        #endregion

        #region Ctors

        public Encryptor(string password)
            : this (password, EncryptorConfiguration.Default)
        {
        }

        /// <summary>
        /// Provides the base implementation for an encryption-authentication encryptor service
        /// </summary>
        /// <param name="password">The password to use for encryption</param>
        public Encryptor(string password, EncryptorConfiguration configuration)
        {
            if (string.IsNullOrEmpty(password))
                throw new ArgumentNullException(nameof(password), "Key may not be null or empty");
            if (!configuration.CheckConfigValid())
                throw new InvalidOperationException("Invalid configuration specified!");

            _password = password;
            Configuration = configuration;

            _encryptor = new TAlgorithm();
            _authenticator = new TAuthenticator();

            SetupConfiguration();
        }

        #endregion

        #region Decrypt

        /// <summary>
        /// Decrypts a stream
        /// </summary>
        /// <param name="stream">The stream to decrypt</param>
        /// <returns></returns>
        public async Task<MemoryStream> DecryptAsync(Stream stream) => await DecryptAsync<MemoryStream>(stream).ConfigureAwait(false);

        /// <summary>
        /// Decrypts a stream
        /// </summary>
        /// <typeparam name="T">The type of stream to decrypt to</typeparam>
        /// <param name="stream">The stream to decrypt</param>
        /// <returns></returns>
        public async Task<T> DecryptAsync<T>(Stream stream) where T : Stream, new()
        {
            CheckDisposed();

            if (stream.IsNullOrEmpty())
                throw new ArgumentNullException(nameof(stream), "Stream cannot be null or empty");

            T returnStream = new T();
            await DecryptAsync(stream, returnStream).ConfigureAwait(false);

            returnStream.Position = 0;
            return returnStream;
        }

        /// <summary>
        /// Decrypts a stream
        /// </summary>
        /// <param name="encryptedStream">The stream to decrypt</param>
        /// <param name="outputStream">The stream to write the decrypted output to</param>
        public async Task DecryptAsync(Stream encryptedStream, Stream outputStream)
        {
            CheckDisposed();

            if (encryptedStream.IsNullOrEmpty())
                throw new ArgumentNullException(nameof(encryptedStream), "Stream cannot be null or empty");
            if (outputStream == null)
                throw new ArgumentNullException(nameof(outputStream));

            try
            {
                #region Authentication

                // Authenticate the stream without peeking and get the remaining data for decryption
                bool authResult = await AuthenticateAsync(encryptedStream, false).ConfigureAwait(false);

                if (!authResult)
                {
                    throw new EncryptionException("Data has been modified after encryption")
                    {
                        Error = EncryptionError.TamperedData
                    };
                }

                #endregion

                #region Get length of data, IVs, Keys and hashes

                // Read the length of the data
                byte[] length = new byte[LENGTH_ALLOCATION_SIZE];
                await encryptedStream.ReadAsync(length, 0, length.Length).ConfigureAwait(false);
                long payloadLength = BitConverter.ToInt64(length, 0);

                // Read the key salt from the stream
                byte[] keySalt = new byte[Configuration.SaltSize];
                await encryptedStream.ReadAsync(keySalt, 0, keySalt.Length).ConfigureAwait(false);

                // Get the encryption key
                _encryptor.Key = EncryptionHelpers.DeriveKey(_password, keySalt, Configuration.KeySize);

                // Read the IV from the stream
                byte[] encryptorIV = new byte[_encryptor.IV.Length];
                await encryptedStream.ReadAsync(encryptorIV, 0, encryptorIV.Length).ConfigureAwait(false);
                _encryptor.IV = encryptorIV;

#if DEBUG_DUMP
                PrintDebugFirst256(encryptedStream, "Stream to decrypt");
                PrintDebugFirst256(encryptedStream, "Stream after authentication, length, key removal", true);
                PrintDebug(length, "Length");
                PrintDebug(keySalt, "KeySalt");
                PrintDebug(_encryptor.Key, "Encryption Key");
                PrintDebug(_encryptor.IV, "Encryptor IV");
                PrintDebugFirst256(encryptedStream, "Encrypted data to decrypt", true);
#endif

                #endregion

                #region Decryption

                using (CryptoStream cs = new CryptoStream(encryptedStream, _encryptor.CreateDecryptor(), CryptoStreamMode.Read))
                    await cs.CopyToAsync(outputStream).ConfigureAwait(false);

#if DEBUG_DUMP
                PrintDebugFirst256(outputStream, "Decrypted data");
#endif

                #endregion
            }
            catch (Exception ex)
            {
                throw new EncryptionException("Error decrypting stream", ex)
                {
                    Error = EncryptionError.DecryptionError
                };
            }
        }

        #endregion

        #region Encrypt

        /// <summary>
        /// Encrypts a stream
        /// </summary>
        /// <param name="stream">The stream to encrypt</param>
        public async Task<MemoryStream> EncryptAsync(Stream stream) => await EncryptAsync<MemoryStream>(stream).ConfigureAwait(false);

        /// <summary>
        /// Encrypts a stream
        /// </summary>
        /// <typeparam name="T">The type of stream to encrypt to</typeparam>
        /// <param name="stream">The stream to encrypt</param>
        public async Task<T> EncryptAsync<T>(Stream stream) where T : Stream, new()
        {
            CheckDisposed();

            if (stream.IsNullOrEmpty())
                throw new ArgumentNullException(nameof(stream), "Stream cannot be null or empty");

            T returnStream = new T();
            await EncryptAsync(stream, returnStream).ConfigureAwait(false);

            returnStream.Position = 0;
            return returnStream;
        }

        /// <summary>
        /// Encrypts a stream
        /// </summary>
        /// <param name="toEncrypt">The stream to encrypt</param>
        /// <param name="outputStream">The stream to write the encrypted output to</param>
        public async Task EncryptAsync(Stream toEncrypt, Stream outputStream)
        {
            CheckDisposed();

            if (toEncrypt.IsNullOrEmpty())
                throw new ArgumentNullException(nameof(toEncrypt), "Stream cannot be null or empty");
            if (toEncrypt.Position == toEncrypt.Length)
                throw new ArgumentException("Input stream is at end", nameof(toEncrypt));
            if (outputStream == null)
                throw new ArgumentNullException(nameof(toEncrypt));

            try
            {
                #region Get IVs and Keys

                // Get a salt for the encryption key
                byte[] keySalt = EncryptionHelpers.GenerateRandomIV(Configuration.SaltSize);
                // Derive the encryption key
                _encryptor.Key = EncryptionHelpers.DeriveKey(_password, keySalt, Configuration.KeySize);

                // Create a new IV for the encryptor
                _encryptor.IV = EncryptionHelpers.GenerateRandomIV(_encryptor.IV.Length);

                // Get a salt for the authentication key
                byte[] authSalt = EncryptionHelpers.GenerateRandomIV(Configuration.SaltSize);
                // Derive the authentication key
                _authenticator.Key = EncryptionHelpers.DeriveKey(_password, authSalt, _authenticator.Key.Length);

                #endregion

                #region Encryption

                long outputStartPos = outputStream.Position;
                int authAllocationsLength = (_authenticator.HashSize / 8) + Configuration.SaltSize;

                // Allocate space for the authentication hash, auth salt and payload length
                await outputStream.WriteAsync(new byte[_authenticator.HashSize / 8], 0, _authenticator.HashSize / 8).ConfigureAwait(false);
                await outputStream.WriteAsync(new byte[Configuration.SaltSize], 0, Configuration.SaltSize).ConfigureAwait(false);
                await outputStream.WriteAsync(new byte[LENGTH_ALLOCATION_SIZE], 0, LENGTH_ALLOCATION_SIZE).ConfigureAwait(false);

                // Write the key salt to the stream
                await outputStream.WriteAsync(keySalt, 0, keySalt.Length).ConfigureAwait(false);
                // Write the IV to the stream
                await outputStream.WriteAsync(_encryptor.IV, 0, _encryptor.IV.Length).ConfigureAwait(false);

                using (MemoryStream outputBuffer = new MemoryStream())
                using (CryptoStream cs = new CryptoStream(outputBuffer, _encryptor.CreateEncryptor(), CryptoStreamMode.Write))
                {
                    await toEncrypt.CopyToAsync(cs).ConfigureAwait(false);
                    cs.FlushFinalBlock();
                    await outputBuffer.CopyAllToAsync(outputStream).ConfigureAwait(false);
                }

                // Write the length of the encryption output stream
                outputStream.Position = outputStartPos + authAllocationsLength;
                byte[] payloadLength = BitConverter.GetBytes(toEncrypt.Length);
                await outputStream.WriteAsync(payloadLength, 0, payloadLength.Length).ConfigureAwait(false);

                #endregion

                #region Authentication

                // Get the hash and write it to the stream
                outputStream.Position = outputStartPos + authAllocationsLength;
                byte[] hash = _authenticator.ComputeHash(outputStream);
                outputStream.Position = outputStartPos;
                await outputStream.WriteAsync(hash, 0, hash.Length).ConfigureAwait(false);

                // Write the auth salt to the stream
                await outputStream.WriteAsync(authSalt, 0, authSalt.Length).ConfigureAwait(false);

                #endregion

#if DEBUG_DUMP
                PrintDebugFirst256(toEncrypt, "Stream to encrypt");
                PrintDebug(payloadLength, "Length");
                PrintDebug(keySalt, "Key Salt");
                PrintDebug(_encryptor.Key, "Encryption Key");
                PrintDebug(_encryptor.IV, "Encryptor IV");
                PrintDebug(hash, "Authenticator Hash");
                PrintDebug(authSalt, "Authenticator Salt");
                PrintDebugFirst256(outputStream, "Encrypted output stream");
#endif

            }
            catch (Exception ex)
            {
                throw new EncryptionException("Error encrypting stream", ex)
                {
                    Error = EncryptionError.EncryptionError
                };
            }
        }

        #endregion

        #region Authenticate

        /// <summary>
        /// Authenticates an encrypted stream
        /// </summary>
        /// <typeparam name="T">The type of stream</typeparam>
        /// <param name="stream">An encrypted stream</param>
        /// <param name="peek">Whether or not to seek through the stream when authenticating</param>
        internal async Task<bool> AuthenticateAsync<T>(T stream, bool peek) where T : Stream
        {
            CheckDisposed();

            if (stream.IsNullOrEmpty())
                throw new ArgumentNullException(nameof(stream), "Stream cannot be null or empty");

            long position = stream.Position;
            int authFieldsLength = (_authenticator.HashSize / 8) + Configuration.SaltSize;

            // Get the hash and auth salt from the stream
            byte[] hash = new byte[_authenticator.HashSize / 8];
            byte[] authSalt = new byte[Configuration.SaltSize];

            await stream.ReadAsync(hash, 0, hash.Length).ConfigureAwait(false);
            await stream.ReadAsync(authSalt, 0, authSalt.Length).ConfigureAwait(false);

            // Get the auth key
            _authenticator.Key = EncryptionHelpers.DeriveKey(_password, authSalt, _authenticator.Key.Length);

            // Compute and check the hash
            byte[] computedHash = _authenticator.ComputeHash(stream);
            bool isValid = true;

            for (int i = 0; i < hash.Length; i++)
            {
                if (hash[i] != computedHash[i])
                {
                    isValid = false;
                    break;
                }
            }

            if (peek)
            {
                stream.Position = position;
                return isValid;
            }
            else
            {
                stream.Position = position + authFieldsLength;
                return isValid;
            }
        }

        /// <summary>
        /// Authenticates an encrypted stream
        /// </summary>
        /// <typeparam name="T">The type of stream</typeparam>
        /// <param name="stream">An encrypted stream</param>
        public async Task<bool> AuthenticateAsync<T>(T stream) where T : Stream => await AuthenticateAsync(stream, true).ConfigureAwait(false);

        #endregion

        /// <summary>
        /// Updates the password used for encryption/decryption
        /// </summary>
        /// <param name="newPassword"></param>
        /// <remarks>This method is useful when using patterns like dependency injection. 
        /// Note that decrypting a stream requires the same password that was used to encrypt it
        /// </remarks>
        public void SetPassword(string newPassword)
        {
            CheckDisposed();
            if (string.IsNullOrEmpty(newPassword))
                throw new ArgumentNullException(nameof(newPassword), "Password may not be null or empty!");

            _password = newPassword;
        }

        protected void SetupConfiguration()
        {
            _encryptor.Mode = Configuration.Mode;
            _encryptor.Padding = Configuration.Padding;
            _encryptor.KeySize = Configuration.GetKeySizeInBits();
        }

        #region Debug printing

#if DEBUG_DUMP

        /// <summary>
        /// Prints a byte array to the debug console
        /// </summary>
        /// <param name="data"></param>
        /// <param name="message"></param>
        private void PrintDebug(byte[] data, string message)
        {
            Debug.WriteLine(message);
            foreach (byte element in data)
                Debug.Write(element.ToString());
            Debug.WriteLine(string.Empty);
            Debug.WriteLine("============");
        }

        /// <summary>
        /// Prints a stream to the debug console
        /// </summary>
        /// <param name="stream"></param>
        /// <param name="message"></param>
        /// <param name="printAll">A value indicating whether the stream should be printed from its beginning or its current position</param>
        private void PrintDebug(Stream stream, string message, bool printAll = false)
        {
            long pos = stream.Position;
            byte[] data;
            if (printAll)
            {
                stream.Position = 0;
                data = new byte[stream.Length];
            } else
            {
                data = new byte[stream.Length - stream.Position];
            }

            stream.Read(data, 0, data.Length);
            PrintDebug(data, message);

            stream.Position = pos;
        }

        /// <summary>
        /// Prints the first 256 bytes of a stream to the debug console
        /// </summary>
        /// <param name="stream"></param>
        /// <param name="message"></param>
        private void PrintDebugFirst256(Stream stream, string message, bool fromCurrentPosition = false)
        {
            long pos = stream.Position;
            byte[] data = new byte[256];

            if (!fromCurrentPosition)
                stream.Position = 0;

            stream.Read(data, 0, data.Length);
            PrintDebug(data, message);

            stream.Position = pos;
        }

#endif

        #endregion

        #region IDisposable Support

        private bool disposedValue = false;

        protected virtual void Dispose(bool disposing)
        {
            if (!disposedValue)
            {
                if (disposing)
                {
                    _encryptor.Dispose();
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

        public void CheckDisposed()
        {
            if (disposedValue)
                throw new ObjectDisposedException(GetType().Name);
        }

        #endregion
    }
}
