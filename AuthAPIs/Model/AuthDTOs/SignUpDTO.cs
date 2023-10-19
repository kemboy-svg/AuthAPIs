using System.ComponentModel.DataAnnotations;

namespace AuthAPIs.Model.AuthDTOs
{
    public class SignUpDTO
    {
        [Required(ErrorMessage = "First Name is required")]
        public string FirstName { get; set; } = null!;

        [Required(ErrorMessage = "Last Name is required")]
        public string LastName { get; set; } = null!;

        [Required(ErrorMessage = "Email is required")]
        [EmailAddress(ErrorMessage = "Invalid email address")]
        public string Email { get; set; } = null!;

        public string? PhoneNo { get; set; }

        [Required(ErrorMessage = "Your Password is required")]
        [StringLength(14, MinimumLength = 6)]
        public string Password { get; set; } = null!;

        [Required(ErrorMessage = "Confirm password is required")]
        [Compare("Password", ErrorMessage = "Passwords do not match")]
        public string ConfirmPassword { get; set; } = null!;
    }
}
