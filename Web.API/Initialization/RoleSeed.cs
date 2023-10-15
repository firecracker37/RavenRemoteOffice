using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Web.API.Constants;
using Web.API.Features.Authentication.Models;

namespace Web.API.Initialization
{
    public class RoleSeed
    {
        public static async Task EnsureCreatedAsync(RoleManager<ApplicationRole> roleManager)
        {
            string[] requiredRoles = Enum.GetValues(typeof(Roles))
                                     .Cast<Roles>()
                                     .Select(r => r.ToString())
                                     .ToArray();

            // Get all roles from the database in one call
            var existingRoles = await roleManager.Roles.Select(r => r.Name).ToListAsync();

            // Determine which roles are missing
            var rolesToCreate = requiredRoles.Except(existingRoles);

            foreach (var roleName in rolesToCreate)
            {
                var role = new ApplicationRole { Name = roleName };
                var result = await roleManager.CreateAsync(role);

                if (!result.Succeeded)
                {
                    throw new Exception($"Failed to create role {roleName}");
                }
            }
        }
    }
}
