using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using StreamEncryptor.Extensions;
using Xunit;

namespace StreamEncryptor.Tests.Extensions
{
    public class StreamExtensionsTests
    {
        [Fact]
        public void TestCopyAllTo()
        {
            using (MemoryStream full = Constants.GetRandomStream())
            using (MemoryStream blank = new MemoryStream())
            {
                full.Seek(0, SeekOrigin.End);

                full.CopyAllTo(blank);

                AssertStreamEqual(full, blank);
            }
        }

        [Fact]
        public async void TestCopyAllToAsync()
        {
            using (MemoryStream full = Constants.GetRandomStream())
            using (MemoryStream blank = new MemoryStream())
            {
                full.Seek(0, SeekOrigin.End);
                await full.CopyAllToAsync(blank).ConfigureAwait(false);

                AssertStreamEqual(full, blank);
            }
        }

        [Fact]
        public void TestIsNullOrEmpty()
        {
            MemoryStream n = null;
            Assert.True(n.IsNullOrEmpty());

            using (MemoryStream ms = new MemoryStream())
            {
                Assert.True(ms.IsNullOrEmpty());
                ms.Write(Constants.RANDOM_BYTES);
                Assert.False(ms.IsNullOrEmpty());
            }
        }

        [Fact]
        public void TestWriteAndReset()
        {
            using (MemoryStream ms = new MemoryStream())
            {
                ms.WriteAndReset(Constants.RANDOM_BYTES);
                Assert.Equal(0, ms.Position);
            }
        }

        [Fact]
        public async void TestWriteAndResetAsync()
        {
            using (MemoryStream ms = new MemoryStream())
            {
                await ms.WriteAndResetAsync(Constants.RANDOM_BYTES).ConfigureAwait(false);
                Assert.Equal(0, ms.Position);
            }
        }

        [Fact]
        public async void TestPeekAsync()
        {
            using (MemoryStream ms = Constants.GetRandomStream())
            {
                byte[] buffer = new byte[Constants.RANDOM_BYTES.Length];
                await ms.PeekAsync(buffer).ConfigureAwait(false);

                Assert.Equal(Constants.RANDOM_BYTES, buffer);
                Assert.Equal(0, ms.Position);
            }
        }

        [Fact]
        public async void TestPeekAsyncWithPosition()
        {
            using (MemoryStream ms = Constants.GetRandomStream())
            {
                byte[] buffer = new byte[Constants.RANDOM_BYTES.Length / 2];
                await ms.PeekAsync(buffer, Constants.RANDOM_BYTES.LongLength / 2).ConfigureAwait(false);

                Assert.Equal(Constants.RANDOM_BYTES.TakeLast(Constants.RANDOM_BYTES.Length / 2), buffer);
                Assert.Equal(0, ms.Position);
            }
        }

        private void AssertStreamEqual(MemoryStream expected, MemoryStream actual)
        {
            Assert.Equal(expected.GetBuffer(), actual.GetBuffer().Take((int)expected.Length));
        }
    }
}
