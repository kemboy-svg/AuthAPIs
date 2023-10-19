using System.ComponentModel.DataAnnotations;

namespace AuthAPIs.Model.AuthDTOs
{
    public class LoginDTO
    {
        [Required(ErrorMessage = "Email is required")]
        [EmailAddress(ErrorMessage = "Invalid email address")]
        public string Email { get; set; } = null!;

        [Required(ErrorMessage = "Password is required")]
        [StringLength(14, MinimumLength = 6)]
        [DataType(DataType.Password)]
        public string Password { get; set; } = null!;
    }
}
