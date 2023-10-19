namespace AuthAPIs.Model.AuthDTOs
{
    public class ForgotPasswordDTO
    {
        public string? Password { get; set; } = null!;

        public string? ConfirmPassword { get; set; } = null!;

        public string? Token { get; set; } = null!;
        public string? Email { get; set; } = null!;
        public string? UserId { get; set; } = null!;
    }
}
