using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Web.API.Features.Authentication.Models;

namespace Web.API.Infrastructure.DbContexts
{
    public class ApplicationDbContext : IdentityDbContext<ApplicationUser, ApplicationRole, string>
    {
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
        : base(options)
        {
        }

        public DbSet<UserProfile> UserProfiles { get; set; }
        public DbSet<UserAddress> UserAddresses { get; set; }
        public DbSet<UserPhone> UserPhones { get; set; }

        protected override void OnModelCreating(ModelBuilder builder)
        {
            base.OnModelCreating(builder);

            // Additional configuration here if needed
        }
    }
}
