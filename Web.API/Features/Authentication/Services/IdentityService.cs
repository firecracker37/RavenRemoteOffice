using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
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
            if (string.IsNullOrEmpty(userId)) return null;

            var user = await _dbContext.Users
                             .Include(u => u.UserProfile)
                             .FirstOrDefaultAsync(u => u.Id == userId);

            if (user == null) return null;
            return user;
        }

        public async Task<ApplicationUser> FindUserByEmailAsync(string email)
        {
            if (string.IsNullOrEmpty(email)) return null;

            var user = await _dbContext.Users
                             .Include(u => u.UserProfile)
                             .FirstOrDefaultAsync(u => u.Email == email);
            if (user == null) return null;
            return user;
        }

        public async Task<IdentityResult> RegisterUserAsync(RegisterUserDTO model)
        {
            if (model == null)
            {
                return IdentityResult.Failed(new IdentityError
                {
                    Code = "NullModel",
                    Description = $"{nameof(model)} cannot be null"
                });
            }

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
            if (model == null) return SignInResult.Failed;

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
            if (string.IsNullOrEmpty(email))
                return new EmailConfirmationTokenResult { Success = false, ErrorMessage = "Email was empty or null" };

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
            if (string.IsNullOrEmpty(userId))
            {
                return IdentityResult.Failed(new IdentityError
                {
                    Code = "NullModel",
                    Description = $"{nameof(userId)} cannot be null"
                });
            }
            if (string.IsNullOrEmpty(token))
            {
                return IdentityResult.Failed(new IdentityError
                {
                    Code = "NullModel",
                    Description = $"{nameof(token)} cannot be null"
                });
            }

            var user = await _userManager.FindByIdAsync(userId);

            if (user == null) return IdentityResult.Failed(new IdentityError { Description = $"User with ID = {userId} cannot be found." });

            var confirmationResult = await _userManager.ConfirmEmailAsync(user, token);

            return confirmationResult;
        }

        public async Task<bool> IsEmailConfirmedAsync(ApplicationUser user)
        {
            if (user == null) return false;

            var foundUser = await _userManager.FindByIdAsync(user.Id);

            if (foundUser == null) return false;

            var result = await _userManager.IsEmailConfirmedAsync(foundUser);

            return result;
        }

        public async Task<IdentityResult> AddUserToRoleAsync(UserWithRoleDTO userWithRole)
        {
            if (userWithRole == null)
            {
                return IdentityResult.Failed(new IdentityError
                {
                    Code = "NullModel",
                    Description = $"{nameof(userWithRole)} cannot be null"
                });
            }
            if (userWithRole.User == null)
            {
                return IdentityResult.Failed(new IdentityError
                {
                    Code = "NullModel",
                    Description = $"{nameof(userWithRole.User)} cannot be null"
                });
            }
            // Check if the role exists in the RoleManager
            if (!await _roleManager.RoleExistsAsync(userWithRole.Role))
            {
                return IdentityResult.Failed(new IdentityError
                {
                    Code = "RoleNotFound",
                    Description = $"Role {userWithRole.Role} does not exist"
                });
            }

            string roleName = userWithRole.Role.ToString();
            var result = await _userManager.AddToRoleAsync(userWithRole.User, roleName);

            return result;
        }

        public async Task<IdentityResult> RemoveUserFromRoleAsync(UserWithRoleDTO userWithRole)
        {
            if (userWithRole == null)
            {
                return IdentityResult.Failed(new IdentityError
                {
                    Code = "NullModel",
                    Description = $"{nameof(userWithRole)} cannot be null"
                });
            }
            if (userWithRole.User == null)
            {
                return IdentityResult.Failed(new IdentityError
                {
                    Code = "NullModel",
                    Description = $"{nameof(userWithRole.User)} cannot be null"
                });
            }
            // Check if the role exists in the RoleManager
            if (!await _roleManager.RoleExistsAsync(userWithRole.Role))
            {
                return IdentityResult.Failed(new IdentityError
                {
                    Code = "RoleNotFound",
                    Description = $"Role {userWithRole.Role} does not exist"
                });
            }

            var result = await _userManager.RemoveFromRoleAsync(userWithRole.User, userWithRole.Role);

            return result;
        }

        public async Task<IList<string>> GetUserRolesAsync(ApplicationUser user)
        {
            if (user == null) return new List<string>();

            var roleNames = await _userManager.GetRolesAsync(user);
            return roleNames.ToList();
        }

        public async Task<bool> IsUserInRole(UserWithRoleDTO userWithRole)
        {
            if (userWithRole == null) return false;
            if (userWithRole.User == null) return false;

            var result = await _userManager.IsInRoleAsync(userWithRole.User, userWithRole.Role);

            return result;
        }

        public async Task<string> RequestPasswordResetAsync(ApplicationUser user)
        {
            if (user == null) return null;
            var token = await _userManager.GeneratePasswordResetTokenAsync(user);
            return token;
        }

        public async Task<IdentityResult> ResetUserPasswordAsync(ResetUserPasswordDTO model)
        {
            var user = await _userManager.FindByIdAsync(model.UserId);
            if (user == null)
            {
                _logger.LogWarning($"Could not update password for user: {model.UserId}. No user with that email address was found.");
                return IdentityResult.Failed(new IdentityError { Description = $"User with email = {model.UserId} cannot be found." });
            }

            var result = await _userManager.ResetPasswordAsync(user, model.Token, model.Password);

            if (result.Succeeded)
            {
                _logger.LogInformation($"Password for user {user.Email} was successfully updated in the database");
            }
            return result;
        }

        public async Task<IdentityResult> ChangeUserPasswordAsync(ApplicationUser user, ChangePasswordDTO model)
        {
            if (user == null)
            {
                _logger.LogError("User is null in ChangeUserPasswordAsync.");
                return IdentityResult.Failed(new IdentityError { Description = "An error occurred while processing your request." });
            }

            var passwordCheck = await _userManager.CheckPasswordAsync(user, model.CurrentPassword);

            if (!passwordCheck)
            {
                _logger.LogWarning($"Incorrect current password for user {user.Id}.");
                return IdentityResult.Failed(new IdentityError { Description = "Incorrect current password." });
            }

            return await _userManager.ChangePasswordAsync(user, model.CurrentPassword, model.NewPassword);
        }

        public async Task<IdentityResult> AddUserPhoneNumberAsync(ApplicationUser user, UserPhone userPhone)
        {
            if (user == null || userPhone == null)
                return IdentityResult.Failed(new IdentityError { Description = "An error occurred while processing your request." });

            // Adding the userPhone to the UserProfile's PhoneNumbers collection
            user.UserProfile.PhoneNumbers.Add(userPhone);

            try
            {
                await _dbContext.SaveChangesAsync();
                return IdentityResult.Success;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "An error occurred while adding phone number for user with ID {UserId}", user.Id);
                return IdentityResult.Failed(new IdentityError { Description = ex.Message });
            }
        }

        public async Task<IdentityResult> RemoveUserPhoneNumberAsync(UserPhone userPhone)
        {
            if (userPhone == null)
                return IdentityResult.Failed(new IdentityError { Description = "An error occurred while processing your request." });

            // Remove the userPhone from the DbContext
            _dbContext.UserPhones.Remove(userPhone);

            try
            {
                await _dbContext.SaveChangesAsync();
                return IdentityResult.Success;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "An error occurred while removing phone number with ID {PhoneId}", userPhone.Id);
                return IdentityResult.Failed(new IdentityError { Description = ex.Message });
            }
        }

        public async Task<IdentityResult> UpdateUserPhoneNumberAsync(UserPhone numberToUpdate)
        {
            if (numberToUpdate == null)
                return IdentityResult.Failed(new IdentityError { Description = "An error occurred while processing your request." });

            if (numberToUpdate.Id <= 0)
                return IdentityResult.Failed(new IdentityError { Description = "Invalid phone number ID." });

            try
            {
                _dbContext.Update(numberToUpdate);
                await _dbContext.SaveChangesAsync();
                return IdentityResult.Success;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "An error occurred while updating phone number with ID {PhoneId}", numberToUpdate.Id);
                return IdentityResult.Failed(new IdentityError { Description = ex.Message });
            }
        }

        public async Task<IdentityResult> AddUserAddressAsync(ApplicationUser user, UserAddress model)
        {
            if (user == null || model == null) return IdentityResult.Failed(new IdentityError { Description = "An error occurred while processing your request." });

            // Adding the userAddress to the UserProfile's Addresses collection
            user.UserProfile.Addresses.Add(model);

            try
            {
                await _dbContext.SaveChangesAsync();
                return IdentityResult.Success;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "An error occurred while adding address for user with ID {UserId}", user.Id);
                return IdentityResult.Failed(new IdentityError { Description = ex.Message });
            }
        }

        public async Task<IdentityResult> RemoveUserAddressAsync(UserAddress model)
        {
            if (model == null)
                return IdentityResult.Failed(new IdentityError { Description = "An error occurred while processing your request." });

            _dbContext.UserAddresses.Remove(model);

            try
            {
                await _dbContext.SaveChangesAsync();
                return IdentityResult.Success;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "An error occurred while removing address number with ID {AddressId}", model.Id);
                return IdentityResult.Failed(new IdentityError { Description = ex.Message });
            }
        }

        public async Task<IdentityResult> UpdateUserAddressAsync(UserAddress addressToUpdate)
        {
            if (addressToUpdate == null || addressToUpdate.Id <= 0)
                return IdentityResult.Failed(new IdentityError { Description = "An error occurred while processing your request." });

            try
            {
                await _dbContext.SaveChangesAsync();
                return IdentityResult.Success;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "An error occurred while updating address with ID {PhoneId}", addressToUpdate.Id);
                return IdentityResult.Failed(new IdentityError { Description = ex.Message });
            }
        }
    }
}
