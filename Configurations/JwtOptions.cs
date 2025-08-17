namespace PocIdentity.Api.Configurations
{
    public class JwtOptions
    {
        public string Issuer { get; set; } = "";
        public string Audience { get; set; } = "";
        public string SecretKey { get; set; } = "";
        public int ExpirationMinutes { get; set; } = 60;
    }
}