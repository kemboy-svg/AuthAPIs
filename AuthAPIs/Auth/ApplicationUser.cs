using Microsoft.AspNetCore.Identity;

namespace AuthAPIs.Auth
{
    public class ApplicationUser:IdentityUser
    {
        public string FirstName { get; set; } = null!;
        public string LastName { get; set; }= null!;

        public DateTime JoinedOn { get; set; } = DateTime.Now;
    }
}
