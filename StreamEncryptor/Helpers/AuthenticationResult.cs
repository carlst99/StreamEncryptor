namespace StreamEncryptor.Helpers
{
    internal struct AuthenticationResult
    {
        public byte[] RemainingStream;
        public bool AuthenticationSuccess;

        public AuthenticationResult(bool result, byte[] remainingStream)
        {
            AuthenticationSuccess = result;
            RemainingStream = remainingStream;
        }

        public void Clear()
        {
            RemainingStream = null;
        }
    }
}
