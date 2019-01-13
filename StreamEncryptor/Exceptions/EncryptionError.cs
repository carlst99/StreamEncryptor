namespace StreamEncryptor.Exceptions
{
    public enum EncryptionError
    {
        /// <summary>
        /// There was an error deriving a key from a string
        /// </summary>
        DeriveKeyError = 0,

        /// <summary>
        /// An error occured while generating a random IV
        /// </summary>
        GenerateIVError = 1,

        /// <summary>
        /// This indicates that data has been tampered with in-between encryption and decryption
        /// </summary>
        TamperedData = 2,

        /// <summary>
        /// An error occured while decrypting data
        /// </summary>
        DecryptionError = 3,

        /// <summary>
        /// An error occured while encrypting data
        /// </summary>
        EncryptionError = 4
    }
}
