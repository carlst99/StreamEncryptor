using System;

namespace StreamEncryptor.Exceptions
{
    public class EncryptionException : Exception
    {
        public EncryptionError Error { get; set; }

        public EncryptionException()
        {
        }

        public EncryptionException(string message)
            : base (message)
        {
        }

        public EncryptionException(string message, Exception innerException)
            : base(message, innerException)
        {
        }

        public override string ToString()
        {
            return Error.ToString() + ": " + base.ToString();
        }
    }
}
