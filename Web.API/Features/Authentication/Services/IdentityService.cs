using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Web.API.Constants;
using Web.API.Features.Authentication.DTOs;
using Web.API.Features.Authentication.Models;
using Web.API.Features.Authentication.Results;
using Web.API.Infrastructure.DbContexts;
using Web.Shared.DTOs;

namespace Web.API.Features.Authentication.Services
{
    public class IdentityService : IIdentityService
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly RoleManager<ApplicationRole> _roleManager;
        private readonly ApplicationDbContext _dbContext;
        private readonly ILogger<IdentityService> _logger;

        public IdentityService(
            UserManager<ApplicationUser> userManager,
            RoleManager<ApplicationRole> roleManager,
            ApplicationDbContext dbContext,
            SignInManager<ApplicationUser> signInManager,
            ILogger<IdentityService> logger)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _dbContext = dbContext;
            _signInManager = signInManager;
            _logger = logger;
        }

        public async Task<ApplicationUser> FindUserByIdAsync(string userId)
        {
            if (string.IsNullOrEmpty(userId)) throw new ArgumentNullException(nameof(userId));

            var user = await _dbContext.Users
                             .Include(u => u.UserProfile)
                             .FirstOrDefaultAsync(u => u.Id == userId);

            if (user == null) return null;
            return user;
        }

        public async Task<ApplicationUser> FindUserByEmailAsync(string email)
        {
            if (string.IsNullOrEmpty(email)) throw new ArgumentNullException(nameof(email));

            var user = await _dbContext.Users
                             .Include(u => u.UserProfile)
                             .FirstOrDefaultAsync(u => u.Email == email);
            if (user == null) return null;
            return user;
        }

        public async Task<IdentityResult> RegisterUserAsync(RegisterUserDTO model)
        {
            if (model == null) throw new ArgumentNullException(nameof(model));

            using (var transaction = await _dbContext.Database.BeginTransactionAsync())
            {
                try
                {
                    var userProfile = new UserProfile
                    {
                        FirstName = model.FirstName,
                        LastName = model.LastName
                    };

                    _dbContext.UserProfiles.Add(userProfile);
                    await _dbContext.SaveChangesAsync();

                    var user = new ApplicationUser
                    {
                        UserName = model.Email,
                        Email = model.Email,
                        UserProfileId = userProfile.Id
                    };

                    var result = await _userManager.CreateAsync(user, model.Password);

                    if (!result.Succeeded)
                    {
                        await transaction.RollbackAsync();
                        return result;
                    }

                    await transaction.CommitAsync();
                    return result;
                }
                catch
                {
                    await transaction.RollbackAsync();
                    throw;
                }
            }
        }

        public async Task<SignInResult> LoginAsync(LoginUserDTO model)
        {
            if (model == null) throw new ArgumentNullException(nameof(model));

            var result = await _signInManager.PasswordSignInAsync(model.Email, model.Password, false, lockoutOnFailure: false);

            if (!result.Succeeded)
            {
                // Handle any errors here if necessary
            }

            return result;
        }

        public async Task LogoutAsync()
        {
            await _signInManager.SignOutAsync();
        }

        public async Task<EmailConfirmationTokenResult> GenerateEmailConfirmationTokenAsync(string email)
        {
            if (string.IsNullOrEmpty(email)) throw new ArgumentNullException(nameof(email));

            var user = await _userManager.FindByEmailAsync(email);

            if (user == null)
                return new EmailConfirmationTokenResult { Success = false, ErrorMessage = "User not found" };

            var emailConfirmationToken = await _userManager.GenerateEmailConfirmationTokenAsync(user);

            return new EmailConfirmationTokenResult
            {
                Success = true,
                User = user,
                Token = emailConfirmationToken
            };
        }

        public async Task<IdentityResult> ConfirmEmailAsync(string userId, string token)
        {
            if (string.IsNullOrEmpty(userId)) throw new ArgumentNullException(nameof(userId));
            if (string.IsNullOrEmpty(token)) throw new ArgumentNullException(nameof(token));

            var user = await _userManager.FindByIdAsync(userId);

            if (user == null) return IdentityResult.Failed(new IdentityError { Description = $"User with ID = {userId} cannot be found." });

            var confirmationResult = await _userManager.ConfirmEmailAsync(user, token);

            return confirmationResult;
        }

        public async Task<bool> IsEmailConfirmedAsync(ApplicationUser user)
        {
            if (user == null) throw new ArgumentNullException(nameof(user));

            var foundUser = await _userManager.FindByIdAsync(user.Id);

            if (foundUser == null) return false;

            var result = await _userManager.IsEmailConfirmedAsync(foundUser);

            return result;
        }

        public async Task<IdentityResult> AddUserToRoleAsync(UserWithRoleDTO userWithRole)
        {
            if (userWithRole == null) throw new ArgumentNullException(nameof(userWithRole));
            if (userWithRole.User == null) throw new ArgumentNullException(nameof(userWithRole.User));
            if (!Enum.IsDefined(typeof(Roles), userWithRole.Role))
                throw new ArgumentOutOfRangeException(nameof(userWithRole.Role), "Invalid role specified");

            string roleName = userWithRole.Role.ToString();
            var result = await _userManager.AddToRoleAsync(userWithRole.User, roleName);

            return result;
        }

        public async Task<IdentityResult> RemoveUserFromRoleAsync(UserWithRoleDTO userWithRole)
        {
            if (userWithRole == null) throw new ArgumentNullException(nameof(userWithRole));
            if (userWithRole.User == null) throw new ArgumentNullException(nameof(userWithRole.User));
            if (!Enum.IsDefined(typeof(Roles), userWithRole.Role))
                throw new ArgumentOutOfRangeException(nameof(userWithRole.Role), "Invalid role specified");

            string roleName = userWithRole.Role.ToString();
            var result = await _userManager.RemoveFromRoleAsync(userWithRole.User, roleName);

            return result;
        }

        public async Task<IList<Roles>> GetUserRolesAsync(ApplicationUser user)
        {
            if (user == null) throw new ArgumentNullException(nameof(user));

            var roleNames = await _userManager.GetRolesAsync(user);
            var roles = roleNames
                .Where(roleName => Enum.TryParse(typeof(Roles), roleName, out _))
                .Select(roleName => (Roles)Enum.Parse(typeof(Roles), roleName))
                .ToList();

            return roles;
        }

        public async Task<bool> IsUserInRole(UserWithRoleDTO userWithRole)
        {
            if (userWithRole == null) throw new ArgumentNullException(nameof(userWithRole));
            if (userWithRole.User == null) throw new ArgumentNullException(nameof(userWithRole.User));
            if (!Enum.IsDefined(typeof(Roles), userWithRole.Role))
                throw new ArgumentOutOfRangeException(nameof(userWithRole.Role), "Invalid role specified");

            var result = await _userManager.IsInRoleAsync(userWithRole.User, userWithRole.Role.ToString());

            return result;
        }
    }
}
