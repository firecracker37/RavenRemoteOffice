using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore.Storage;
using Web.API.Features.Authentication.Models;
using Web.API.Infrastructure.DbContexts;

namespace Web.API.Initialization
{
    public class UserSeed
    {
        public static async Task EnsureCreatedAsync(
            UserManager<ApplicationUser> userManager,
            RoleManager<ApplicationRole> roleManager,
            ApplicationDbContext dbContext) // Add parameter for DbContext
        {
            var users = new[]
            {
                new { Email = "admin@test.com", Password = "Test123*", Role = "Admin", FirstName = "Admin", LastName = "McAdmin" },
                new { Email = "manager@test.com", Password = "Test123*", Role = "Manager", FirstName = "Manager", LastName = "McManager" },
                new { Email = "supervisor@test.com", Password = "Test123*", Role = "Supervisor", FirstName = "Supervisor", LastName = "McSupervisor" },
                new { Email = "employee@test.com", Password = "Test123*", Role = "Employee", FirstName = "Employee", LastName = "McEmployee" },
                new { Email = "inactive@test.com", Password = "Test123*", Role = "Inactive", FirstName = "Inactive", LastName = "McInactive" }
                // Add more users as needed
            };

            using (IDbContextTransaction transaction = await dbContext.Database.BeginTransactionAsync()) // Begin transaction
            {
                try
                {
                    foreach (var user in users)
                    {
                        if (await userManager.FindByEmailAsync(user.Email) == null)
                        {
                            // Create UserProfile first
                            var userProfile = new UserProfile { FirstName = user.FirstName, LastName = user.LastName };
                            dbContext.UserProfiles.Add(userProfile);
                            await dbContext.SaveChangesAsync();

                            var applicationUser = new ApplicationUser
                            {
                                UserName = user.Email,
                                Email = user.Email,
                                EmailConfirmed = true,
                                UserProfileId = userProfile.Id, // Set UserProfileId
                                UserProfile = userProfile // Set UserProfile
                            };

                            var result = await userManager.CreateAsync(applicationUser, user.Password);
                            if (result.Succeeded)
                            {
                                if (await roleManager.RoleExistsAsync(user.Role))
                                {
                                    await userManager.AddToRoleAsync(applicationUser, user.Role);
                                }
                                else
                                {
                                    throw new Exception($"Role {user.Role} does not exist.");
                                }
                            }
                            else
                            {
                                throw new Exception($"Failed to create user {user.Email}");
                            }
                        }
                    }

                    transaction.Commit(); // Commit transaction if everything is successful
                }
                catch
                {
                    transaction.Rollback(); // Rollback transaction in case of error
                    throw;
                }
            }
        }
    }
}
