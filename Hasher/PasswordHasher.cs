using System.Security.Cryptography;
using System.Text;

namespace SecurePassword.Hasher
{

    public class PasswordHasher
    {
        private readonly int _iterations;
        private readonly string _pepper;

        public PasswordHasher(int iterations, string pepper)
        {
            _iterations = iterations;
            _pepper = pepper;
        }

        public (string Hash, string Salt) HashPassword(string password)
        {
            byte[] saltBytes = new byte[16];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(saltBytes);
            }

            string salt = Convert.ToBase64String(saltBytes);
            string hashedPassword = HashPasswordWithSaltAndPepper(password, salt);

            return (hashedPassword, salt);
        }

        private string HashPasswordWithSaltAndPepper(string password, string salt)
        {
            using var sha256 = SHA256.Create();

            string combined = salt + _pepper + password;
            byte[] hashBytes = Encoding.UTF8.GetBytes(combined);

            for (int i = 0; i < _iterations; i++)
            {
                hashBytes = sha256.ComputeHash(hashBytes);
            }

            return Convert.ToBase64String(hashBytes);
        }

        public bool VerifyPassword(string password, string salt, string storedHash)
        {
            string hashedPassword = HashPasswordWithSaltAndPepper(password, salt);
            return hashedPassword == storedHash;
        }
    }

}
