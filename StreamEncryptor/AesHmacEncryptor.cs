using StreamEncryptor.Base;
using StreamEncryptor.Exceptions;
using StreamEncryptor.Extensions;
using System;
using System.IO;
using System.Security.Cryptography;
using System.Threading.Tasks;

namespace StreamEncryptor
{
    public class AesHmacEncryptor : Encryptor
    {
        public AesHmacEncryptor(string key)
            : base(key)
        {
            _encryptor = Aes.Create();
            _encryptor.Mode = CipherMode.CBC;
            _encryptor.Padding = PaddingMode.PKCS7;

            _authenticator = new HMACSHA256();
        }

        /// <summary>
        /// Decrypts a stream
        /// </summary>
        /// <typeparam name="T">The type of stream to return the decrypted data as</typeparam>
        /// <param name="stream">The stream to decrypt</param>
        /// <returns></returns>
        public override async Task<T> DecryptAsync<T>(Stream stream)
        {
            await base.DecryptAsync<T>(stream).ConfigureAwait(false);

            try
            {
                stream.Position = 0;

                #region Authentication

                if (!await AuthenticateAsync(stream, false).ConfigureAwait(false))
                {
                    throw new EncryptionException("Data has been modified after encryption")
                    {
                        Error = EncryptionError.TamperedData
                    };
                }

                #endregion

                #region Get IVs, Keys and hashes

                // Read the key IV from the stream
                byte[] keySalt = new byte[SALT_SIZE];
                await stream.ReadAsync(keySalt, 0, keySalt.Length).ConfigureAwait(false);
                // Get the encryption key
                _encryptor.Key = DeriveKey(_password, keySalt);

                // Read the IV from the stream
                await stream.ReadAsync(_encryptor.IV, 0, _encryptor.IV.Length).ConfigureAwait(false);

                #endregion

                T decryptedSecret = new T();

                #region Decryption

                using (CryptoStream cs = new CryptoStream(stream, _encryptor.CreateDecryptor(), CryptoStreamMode.Read))
                {
                    byte[] buff = new byte[BUFFER_READ_LENGTH];

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
        /// Serializes and encrypts an <see cref="IEntity"/>
        /// </summary>
        /// <param name="entity">The entity to be encrypted</param>
        /// <returns>A stream of the encrypted data</returns>
        public override async Task<T> EncryptAsync<T>(Stream stream)
        {
            await base.EncryptAsync<T>(stream).ConfigureAwait(false);

            try
            {
                #region Get IVs and Keys

                // Get a salt for the encryption key
                byte[] keySalt = GenerateRandomIV();
                // Derive the encryption key
                _encryptor.Key = DeriveKey(_password, keySalt);

                // Create a new IV for the encryptor
                _encryptor.IV = GenerateRandomIV();

                // Get a salt for the authentication key
                byte[] authSalt = GenerateRandomIV();
                // Derive the authentication key
                _authenticator.Key = DeriveKey(_password, authSalt);

                #endregion

                #region Encryption

                MemoryStream ms = new MemoryStream(); // Encrypted stream
                CryptoStream cs = new CryptoStream(ms, _encryptor.CreateEncryptor(), CryptoStreamMode.Write); // Encryptor stream

                // Write the key salt to the stream
                await ms.WriteAsync(keySalt, 0, keySalt.Length).ConfigureAwait(false);
                // Write the IV to the stream
                await ms.WriteAsync(_encryptor.IV, 0, _encryptor.IV.Length).ConfigureAwait(false);

                byte[] streamBuffer = new byte[stream.Length];
                stream.Read(streamBuffer, 0, streamBuffer.Length);

                // Write the secret to the stream
                await cs.WriteAsync(streamBuffer, 0, streamBuffer.Length).ConfigureAwait(false);

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
        /*internal override async Task<bool> AuthenticateAsync<T>(T stream, bool peek)
        {
            await base.AuthenticateAsync(stream, peek).ConfigureAwait(false);

            // Get the hash and auth salt from the stream
            byte[] hash = new byte[_authenticator.HashSize / 8];
            byte[] authSalt = new byte[SALT_SIZE];
            if (peek)
            {
                await stream.PeekAsync(hash).ConfigureAwait(false);
                await stream.PeekAsync(authSalt, hash.LongLength).ConfigureAwait(false);
            }
            else
            {
                await stream.ReadAsync(hash, 0, hash.Length).ConfigureAwait(false);
                await stream.ReadAsync(authSalt, 0, authSalt.Length).ConfigureAwait(false);
            }

            // Get the auth key
            _authenticator.Key = DeriveKey(_password, authSalt);

            // Determine where we need to read from
            long actualPosition = 0;
            if (peek)
                actualPosition = hash.LongLength + authSalt.LongLength;
            else
                actualPosition = stream.Position;

            // Get the buffer to authenticate
            byte[] buffer = new byte[stream.Length - actualPosition];
            await stream.PeekAsync(buffer, actualPosition).ConfigureAwait(false);

            // Compute and check the hash
            byte[] computedHash = _authenticator.ComputeHash(buffer);
            bool isValid = true;

            for (int i = 0; i < hash.Length; i++)
            {
                if (hash[i] != computedHash[i])
                    isValid = false;
            }

            return isValid;
        }*/

        /// <summary>
        /// Authenticates an encrypted stream
        /// </summary>
        /// <typeparam name="T">The type of stream</typeparam>
        /// <param name="stream">An encrypted stream</param>
        /// <param name="peek">Whether or not to seek through the stream when authenticating</param>
        /// <returns></returns>
        internal override async Task<bool> AuthenticateAsync<T>(T stream, bool peek)
        {
            await base.AuthenticateAsync(stream, peek).ConfigureAwait(false);
            long position = stream.Position;

            // Get the hash and auth salt from the stream
            byte[] hash = new byte[_authenticator.HashSize / 8];
            byte[] authSalt = new byte[SALT_SIZE];

            await stream.ReadAsync(hash, 0, hash.Length).ConfigureAwait(false);
            await stream.ReadAsync(authSalt, 0, authSalt.Length).ConfigureAwait(false);

            // Get the auth key
            _authenticator.Key = DeriveKey(_password, authSalt);

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
            if (peek)
                stream.Position = position;
            else
                stream.Position = hash.LongLength + authSalt.LongLength;

            return isValid;
        }
    }
}
