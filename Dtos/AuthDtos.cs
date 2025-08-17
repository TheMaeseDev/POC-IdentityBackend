namespace PocIdentity.Api.Dtos
{
    public class LoginRequestDto
    {
        public string UserName { get; set; } = "";
        public string Password { get; set; } = "";
    }

    public class RegisterUserDto
    {
        public string UserName { get; set; } = "";
        public string Email { get; set; } = "";
        public string Password { get; set; } = "";
        public string Role { get; set; } = "Viewer"; // por defecto
    }

    public class AuthResponseDto
    {
        public string AccessToken { get; set; } = "";
        public DateTime ExpiresAt { get; set; }
        public string UserName { get; set; } = "";
        public string[] Roles { get; set; } = Array.Empty<string>();
    }
}
