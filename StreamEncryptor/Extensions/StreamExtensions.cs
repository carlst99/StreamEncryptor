﻿using System.IO;
using System.Threading.Tasks;

namespace StreamEncryptor.Extensions
{
    public static class StreamExtensions
    {
        /// <summary>
        /// Copies the entirety of this stream to another, regardless of the position of this stream
        /// </summary>
        /// <param name="me"></param>
        /// <param name="stream">The stream to copy to</param>
        public static void CopyAllTo(this Stream me, Stream stream)
        {
            long position = me.Position;
            me.Position = 0;
            me.CopyTo(stream);
            me.Position = position;
        }

        /// <summary>
        /// Copies the entirety of this stream to another, regardless of the position of this stream
        /// </summary>
        /// <param name="me"></param>
        /// <param name="stream">The stream to copy to</param>
        public static async Task CopyAllToAsync(this Stream me, Stream stream)
        {
            long position = me.Position;
            me.Position = 0;
            await me.CopyToAsync(stream).ConfigureAwait(false);
            me.Position = position;
        }

        /// <summary>
        /// Checks if a stream is null or empty
        /// </summary>
        /// <param name="stream"></param>
        /// <returns>True if null or empty</returns>
        public static bool IsNullOrEmpty(this Stream stream)
        {
            if (stream == null)
                return true;
            else if (stream.Length <= 0)
                return true;
            else
                return false;
        }

        /// <summary>
        /// Writes a byte array to the stream and resets its position
        /// </summary>
        /// <param name="stream">The stream to write to</param>
        /// <param name="data">The data to write</param>
        public static void WriteAndReset(this Stream stream, byte[] data)
        {
            long position = stream.Position;
            stream.Write(data, 0, data.Length);
            stream.Position = position;
        }

        /// <summary>
        /// Writes a byte array to the stream and resets its position
        /// </summary>
        /// <param name="stream">The stream to write to</param>
        /// <param name="data">The data to write</param>
        public static async Task WriteAndResetAsync(this Stream stream, byte[] data)
        {
            long position = stream.Position;
            await stream.WriteAsync(data, 0, data.Length);
            stream.Position = position;
        }
    }
}
