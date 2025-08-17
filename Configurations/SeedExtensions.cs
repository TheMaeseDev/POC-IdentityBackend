using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using PocIdentity.Api.Models;

namespace PocIdentity.Api.Configurations
{
    public static class SeedExtensions
    {
        public static async Task SeedDefaultsAsync(this IServiceProvider services)
        {
            using var scope = services.CreateScope();
            var roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<IdentityRole>>();
            var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();

            string[] roles = new[] { "Admin", "Stock", "Viewer" };
            foreach (var role in roles)
            {
                if (!await roleManager.RoleExistsAsync(role))
                    await roleManager.CreateAsync(new IdentityRole(role));
            }

            // Usuario admin de prueba (cambiá en prod)
            var admin = await userManager.FindByNameAsync("admin");
            if (admin == null)
            {
                admin = new ApplicationUser
                {
                    UserName = "admin",
                    Email = "admin@local",
                    EmailConfirmed = true
                };
                var create = await userManager.CreateAsync(admin, "Admin123$");
                if (create.Succeeded)
                    await userManager.AddToRoleAsync(admin, "Admin");
            }
        }
    }
}