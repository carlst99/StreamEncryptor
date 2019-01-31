using System;
using System.IO;
using System.Runtime.CompilerServices;
using System.Threading.Tasks;

[assembly: InternalsVisibleTo("StreamEncryptor.Tests")]

namespace StreamEncryptor
{
    public interface IEncryptor : IDisposable
    {
        /// <summary>
        /// Decrypts a stream
        /// </summary>
        /// <typeparam name="T">The type of stream to decrypt to</typeparam>
        /// <param name="stream">The stream to decrypt</param>
        /// <returns></returns>
        Task<T> DecryptAsync<T>(Stream stream) where T : Stream, new();

        /// <summary>
        /// Decrypts a stream
        /// </summary>
        /// <param name="encryptedStream">The stream to decrypt</param>
        /// <param name="outputStream">The stream to write the decrypted output to</param>
        Task DecryptAsync(Stream encryptedStream, Stream outputStream);

        /// <summary>
        /// Encrypts a stream
        /// </summary>
        /// <typeparam name="T">The type of stream to encrypt to</typeparam>
        /// <param name="stream">The stream to encrypt</param>
        /// <returns></returns>
        Task<T> EncryptAsync<T>(Stream stream) where T : Stream, new();

        /// <summary>
        /// Authenticates an encrypted stream
        /// </summary>
        /// <typeparam name="T">The type of stream</typeparam>
        /// <param name="stream">An encrypted stream</param>
        /// <returns></returns>
        Task<bool> AuthenticateAsync<T>(T stream) where T : Stream;
    }
}
