using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using PocIdentity.Api.Dtos;
using PocIdentity.Api.Services;

namespace PocIdentity.Api.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly IAuthService _auth;
        public AuthController(IAuthService auth) => _auth = auth;

        [HttpPost("login")]
        [AllowAnonymous]
        public async Task<IActionResult> Login([FromBody] LoginRequestDto dto)
        {
            var result = await _auth.LoginAsync(dto);
            if (result == null) return Unauthorized(new { message = "Usuario o contraseña inválidos" });
            return Ok(result);
        }

        [HttpPost("register")]
        [Authorize(Roles = "Admin")]
        public async Task<IActionResult> Register([FromBody] RegisterUserDto dto)
        {
            var (succ, errors) = await _auth.RegisterAsync(dto);
            if (!succ) return BadRequest(new { errors });
            return Created(string.Empty, new { message = "Usuario creado" });
        }
    }
}
