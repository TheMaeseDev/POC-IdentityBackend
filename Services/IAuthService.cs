using PocIdentity.Api.Dtos;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using PocIdentity.Api.Configurations;
using PocIdentity.Api.Models;

namespace PocIdentity.Api.Services
{
    public interface IAuthService
    {
        Task<AuthResponseDto?> LoginAsync(LoginRequestDto dto);
        Task<(bool Succeeded, IEnumerable<string> Errors)> RegisterAsync(RegisterUserDto dto);
    }
}
