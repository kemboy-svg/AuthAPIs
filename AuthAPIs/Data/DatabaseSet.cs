using AuthAPIs.Auth;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace AuthAPIs.Data
{
    public class DatabaseSet : IdentityDbContext<ApplicationUser>
    {
       
      
       
        public DatabaseSet(DbContextOptions<DatabaseSet> options) : base(options)
        {
        }

       


    }
}
