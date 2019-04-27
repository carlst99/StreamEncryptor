namespace StreamEncryptor.Helpers
{
    internal struct AuthenticationResult
    {
        internal byte[] Buffer;
        public bool AuthenticationSuccess;

        public AuthenticationResult(bool result, byte[] remainingStream)
        {
            AuthenticationSuccess = result;
            Buffer = remainingStream;
        }
    }
}
