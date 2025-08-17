using PocIdentity.Api.Models;

namespace PocIdentity.Api.Repositories
{
    public interface IUserRepository
    {
        Task<ApplicationUser?> GetByIdAsync(string id);
    }
}
