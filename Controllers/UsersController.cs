using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace PocIdentity.Api.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class UsersController : ControllerBase
    {
        [HttpGet("me")]
        [Authorize]
        public IActionResult Me()
        {
            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            var userName = User.Identity?.Name;
            var roles = User.FindAll(ClaimTypes.Role).Select(c => c.Value);
            return Ok(new { userId, userName, roles });
        }

        [HttpGet("admin-stuff")]
        [Authorize(Roles = "Admin")]
        public IActionResult AdminStuff() => Ok(new { msg = "Solo Admin puede ver esto" });

        [HttpGet("stock-stuff")]
        [Authorize(Roles = "Stock")]
        public IActionResult StockStuff() => Ok(new { msg = "Solo Stock puede ver esto" });
    }
}
