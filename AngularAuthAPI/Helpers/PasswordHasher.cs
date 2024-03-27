using System.Security.Cryptography;

namespace AngularAuthAPI.Helpers
{

    public class PasswordHasher
    {
        
        private static RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();
        private static readonly int SaltSize = 16;
        private static readonly int HashSize = 20;
        private static readonly int Iterations = 10000;

        public static string HashPassword(string password)
        {
            byte[] salt;
            rng.GetBytes(salt = new byte[SaltSize]);
            var key = new Rfc2898DeriveBytes(password, salt, Iterations);
            var hash = key.GetBytes(HashSize);

            var HashBytes = new byte[SaltSize + HashSize];
            Array.Copy(salt, 0, HashBytes, 0, SaltSize);
            Array.Copy(hash, 0, HashBytes, SaltSize, HashSize);

            var base64Hash = Convert.ToBase64String(HashBytes);

            return base64Hash;

        }
        public static bool VerifyPassword(string password, string hashedPassword)
        {
            var HashBytes = Convert.FromBase64String(hashedPassword);
            var salt = new byte[SaltSize];
            Array.Copy(HashBytes, 0, salt, 0, SaltSize);
            var key = new Rfc2898DeriveBytes(password, salt, Iterations);
            var hash = key.GetBytes(HashSize);
            for (int i = 0; i < HashSize; i++)
            {
                if (HashBytes[i + SaltSize] != hash[i])
                {
                    return false;
                }
            }
            return true;
        }   

    }
}
