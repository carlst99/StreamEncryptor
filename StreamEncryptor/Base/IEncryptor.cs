using System;
using System.IO;
using System.Threading.Tasks;

namespace StreamEncryptor.Base
{
    public interface IEncryptor : IDisposable
    {
        /// <summary>
        /// Decrypts a stream
        /// </summary>
        /// <typeparam name="T">The type of stream to decrypt to</typeparam>
        /// <param name="stream">The stream to decrypt</param>
        /// <returns></returns>
        Task<T> Decrypt<T>(Stream stream) where T : Stream, new();

        /// <summary>
        /// Encrypts a stream
        /// </summary>
        /// <typeparam name="T">The type of stream to encrypt to</typeparam>
        /// <param name="stream">The stream to encrypt</param>
        /// <returns></returns>
        Task<T> Encrypt<T>(Stream stream) where T : Stream, new();

        /// <summary>
        /// Authenticates an encrypted stream
        /// </summary>
        /// <typeparam name="T">The type of stream</typeparam>
        /// <param name="stream">An encrypted stream</param>
        /// <returns></returns>
        Task<bool> Authenticate<T>(T stream) where T : Stream;
    }
}
