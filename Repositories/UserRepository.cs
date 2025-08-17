using Microsoft.AspNetCore.Identity;
using PocIdentity.Api.Models;

namespace PocIdentity.Api.Repositories
{
    public class UserRepository : IUserRepository
    {
        private readonly UserManager<ApplicationUser> _userManager;
        public UserRepository(UserManager<ApplicationUser> userManager) => _userManager = userManager;

        public Task<ApplicationUser?> GetByIdAsync(string id) => _userManager.FindByIdAsync(id);
    }
}