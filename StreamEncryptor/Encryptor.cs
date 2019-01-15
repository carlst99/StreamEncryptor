﻿using StreamEncryptor.Exceptions;
using StreamEncryptor.Extensions;
using StreamEncryptor.Helpers;
using System;
using System.IO;
using System.Security.Cryptography;
using System.Threading.Tasks;

namespace StreamEncryptor
{
    public class Encryptor<TAlgorithm, TAuthenticator> : IEncryptor
        where TAlgorithm : SymmetricAlgorithm, new()
        where TAuthenticator : HMAC, new()
    {
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

            _password = password;
            Configuration = configuration;

            _encryptor = new TAlgorithm();
            _authenticator = new TAuthenticator();

            SetupConfiguration();
        }

        #endregion

        /// <summary>
        /// When overriden in a derived class, decrypts a stream
        /// </summary>
        /// <typeparam name="T">The type of stream to decrypt to</typeparam>
        /// <param name="stream">The stream to decrypt</param>
        /// <returns></returns>
        public async Task<T> DecryptAsync<T>(Stream stream) where T : Stream, new()
        {
            CheckDisposed();

            if (stream.IsNullOrEmpty())
                throw new ArgumentNullException("Stream cannot be null or empty");

            try
            {
                stream.Position = 0;

                #region Authentication

                AuthenticationResult authenticationResult = await AuthenticateAsync(stream, false).ConfigureAwait(false);

                if (!authenticationResult.AuthenticationSuccess)
                {
                    throw new EncryptionException("Data has been modified after encryption")
                    {
                        Error = EncryptionError.TamperedData
                    };
                }

                #endregion

                MemoryStream remainingStream = new MemoryStream(authenticationResult.RemainingStream);

                #region Get IVs, Keys and hashes

                // Read the key IV from the stream
                byte[] keySalt = new byte[Configuration.SaltSize];
                await remainingStream.ReadAsync(keySalt, 0, keySalt.Length).ConfigureAwait(false);
                // Get the encryption key
                _encryptor.Key = EncryptionHelpers.DeriveKey(_password, keySalt, Configuration.KeySize);

                // Read the IV from the stream
                await remainingStream.ReadAsync(_encryptor.IV, 0, _encryptor.IV.Length).ConfigureAwait(false);

                #endregion

                T decryptedSecret = new T();

                #region Decryption

                using (CryptoStream cs = new CryptoStream(remainingStream, _encryptor.CreateDecryptor(), CryptoStreamMode.Read))
                {
                    byte[] buff = new byte[Configuration.BufferSize];

                    while (cs.Read(buff, 0, buff.Length) != 0)
                    {
                        await decryptedSecret.WriteAsync(buff, 0, buff.Length).ConfigureAwait(false);
                    }

                    decryptedSecret.Position = 0;
                }

                #endregion

                decryptedSecret.Position = 0;
                return decryptedSecret;
            }
            catch (Exception ex)
            {
                throw new EncryptionException("Error decrypting stream", ex)
                {
                    Error = EncryptionError.DecryptionError
                };
            }
        }

        /// <summary>
        /// When overriden in a derived class, encrypts a stream
        /// </summary>
        /// <typeparam name="T">The type of stream to encrypt to</typeparam>
        /// <param name="stream">The stream to encrypt</param>
        /// <returns></returns>
        public async Task<T> EncryptAsync<T>(Stream stream) where T : Stream, new()
        {
            CheckDisposed();

            if (stream.IsNullOrEmpty())
                throw new ArgumentNullException("Stream cannot be null or empty");

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

                MemoryStream ms = new MemoryStream(); // Encrypted stream
                CryptoStream cs = new CryptoStream(ms, _encryptor.CreateEncryptor(), CryptoStreamMode.Write); // Encryptor stream

                // Write the key salt to the stream
                await ms.WriteAsync(keySalt, 0, keySalt.Length).ConfigureAwait(false);
                // Write the IV to the stream
                await ms.WriteAsync(_encryptor.IV, 0, _encryptor.IV.Length).ConfigureAwait(false);

                byte[] streamBuffer = new byte[Configuration.BufferSize];
                while (stream.Read(streamBuffer, 0, streamBuffer.Length) > 0)
                {
                    await cs.WriteAsync(streamBuffer, 0, streamBuffer.Length).ConfigureAwait(false);
                }

                // Flush buffers
                await cs.FlushAsync().ConfigureAwait(false);
                cs.FlushFinalBlock();

                #endregion

                T returnStream = new T();

                #region Authentication

                // Get the buffer of ms
                byte[] buffer = new byte[ms.Length];
                ms.Position = 0;
                await ms.ReadAsync(buffer, 0, buffer.Length).ConfigureAwait(false);

                // Get the hash and write it to the stream
                byte[] hash = _authenticator.ComputeHash(buffer);
                await returnStream.WriteAsync(hash, 0, hash.Length).ConfigureAwait(false);

                // Write the auth salt to the stream
                await returnStream.WriteAsync(authSalt, 0, authSalt.Length).ConfigureAwait(false);

                #endregion

                #region FinaliseReturn

                await returnStream.WriteAndResetAsync(buffer).ConfigureAwait(false);

                // Dispose of sw and underlying streams
                cs.Dispose();

                #endregion

                returnStream.Position = 0;
                return returnStream;
            }
            catch (Exception ex)
            {
                throw new EncryptionException("Error encrypting stream", ex)
                {
                    Error = EncryptionError.EncryptionError
                };
            }
        }

        /// <summary>
        /// Authenticates an encrypted stream
        /// </summary>
        /// <typeparam name="T">The type of stream</typeparam>
        /// <param name="stream">An encrypted stream</param>
        /// <param name="peek">Whether or not to seek through the stream when authenticating</param>
        /// <returns></returns>
        internal async Task<AuthenticationResult> AuthenticateAsync<T>(T stream, bool peek) where T : Stream
        {
            CheckDisposed();

            if (stream.IsNullOrEmpty())
                throw new ArgumentNullException("Stream cannot be null or empty");
            long position = stream.Position;

            // Get the hash and auth salt from the stream
            byte[] hash = new byte[_authenticator.HashSize / 8];
            byte[] authSalt = new byte[Configuration.SaltSize];

            await stream.ReadAsync(hash, 0, hash.Length).ConfigureAwait(false);
            await stream.ReadAsync(authSalt, 0, authSalt.Length).ConfigureAwait(false);

            // Get the auth key
            _authenticator.Key = EncryptionHelpers.DeriveKey(_password, authSalt, _authenticator.Key.Length);

            // Get the buffer to authenticate
            byte[] buffer = new byte[stream.Length - stream.Position];
            await stream.ReadAsync(buffer, 0, buffer.Length).ConfigureAwait(false);

            // Compute and check the hash
            byte[] computedHash = _authenticator.ComputeHash(buffer);
            bool isValid = true;

            for (int i = 0; i < hash.Length; i++)
            {
                if (hash[i] != computedHash[i])
                    isValid = false;
            }

            // Return the stream position
            /*if (peek)
                stream.Position = position;
            else
                stream.Position = hash.LongLength + authSalt.LongLength;*/

            if (peek)
            {
                stream.Position = position;
                return new AuthenticationResult(isValid, null);
            }
            else
            {
                return new AuthenticationResult(isValid, buffer);
            }
        }

        /// <summary>
        /// Authenticates an encrypted stream
        /// </summary>
        /// <typeparam name="T">The type of stream</typeparam>
        /// <param name="stream">An encrypted stream</param>
        /// <returns></returns>
        public async Task<bool> AuthenticateAsync<T>(T stream) where T : Stream
        {
            AuthenticationResult result = await AuthenticateAsync(stream, true).ConfigureAwait(false);
            return result.AuthenticationSuccess;
        }

        protected void SetupConfiguration()
        {
            _encryptor.Mode = Configuration.Mode;
            _encryptor.Padding = Configuration.Padding;
            _encryptor.KeySize = Configuration.GetKeySizeInBits();
        }

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
