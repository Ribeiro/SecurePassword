using Microsoft.Extensions.Configuration;
using SecurePassword.Hasher;

namespace SecurePassword.Main
{
    public class Program
    {

        protected Program() { }

        static void Main(string[] args)
        {
            var builder = new ConfigurationBuilder().AddUserSecrets<Program>();
            var configuration = builder.Build();
            string pepper = configuration["Pepper"] ?? throw new InvalidOperationException("Pepper is not set");
            int iterations = int.TryParse(configuration["Security:Iterations"], out int parsedIterations)
                                    ? parsedIterations
                                    : 10000;

            PasswordHasher passwordHasher = new PasswordHasher(iterations, pepper);

            Console.Write("Digite a senha: ");
            string password = Console.ReadLine() ?? string.Empty;

            var (hash, salt) = passwordHasher.HashPassword(password);
            Console.WriteLine($"Hash: {hash}");
            Console.WriteLine($"Salt: {salt}");

            Console.Write("Digite a senha novamente para verificação: ");
            string verifyPassword = Console.ReadLine() ?? string.Empty;

            bool isVerified = passwordHasher.VerifyPassword(verifyPassword, salt, hash);
            Console.WriteLine($"Senha verificada: {isVerified}");
        }
    }
}
