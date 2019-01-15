using StreamEncryptor.Exceptions;
using System;
using System.Security.Cryptography;

namespace StreamEncryptor.Helpers
{
    public static class EncryptionHelpers
    {
        /// <summary>
        /// Turns a string into a cryptographically-secure byte[] array
        /// </summary>
        /// <returns>A <see cref="byte"/> array containing the derived key</returns>
        public static byte[] DeriveKey(string key, byte[] salt, int keySize)
        {
            if (string.IsNullOrEmpty(key))
                throw new ArgumentNullException("key may not be null or empty");

            try
            {
                using (Rfc2898DeriveBytes deriver = new Rfc2898DeriveBytes(key, salt))
                {
                    return deriver.GetBytes(keySize);
                }
            }
            catch (Exception ex)
            {
                throw new EncryptionException("Error deriving key", ex)
                {
                    Error = EncryptionError.DeriveKeyError
                };
            }
        }

        /// <summary>
        /// Generates a random IV of length <see cref="SALT_SIZE"/>
        /// </summary>
        /// <returns>A <see cref="byte"/> array of length <see cref="SALT_SIZE"/> containing a randomly generated, cryptographically secure IV
        public static byte[] GenerateRandomIV(int saltSize)
        {
            byte[] iv = new byte[saltSize];
            try
            {
                using (RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider())
                    rng.GetBytes(iv);
            }
            catch (CryptographicException ex)
            {
                throw new EncryptionException("Error generating IV", ex)
                {
                    Error = EncryptionError.GenerateIVError
                };
            }
            return iv;
        }
    }
}
