using Microsoft.Extensions.DependencyInjection;
using VehicleRegistryAPI.Models;
using VehicleRegistryAPI.Services;

namespace VehicleRegistryAPI.Data;

public static class DataSeeder
{
    public static async Task SeedAdminUserAsync(IServiceProvider serviceProvider)
    {
        using var scope = serviceProvider.CreateScope();
        var context = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
        var passwordHasher = scope.ServiceProvider.GetRequiredService<IPasswordHasher>();

        // Ensure database exists (works for InMemory and relational providers)
        await context.Database.EnsureCreatedAsync();

        if (!context.Users.Any(u => u.Role == "Admin"))
        {
            var admin = new User
            {
                Username = "admin@gmail.com",
                PasswordHash = passwordHasher.HashPassword("TempAdminPassword123!"),
                Role = "Admin",
                ForcePasswordReset = true
            };

            context.Users.Add(admin);
            await context.SaveChangesAsync();
        }
    }
}
