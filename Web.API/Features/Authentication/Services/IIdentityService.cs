using Microsoft.AspNetCore.Identity;
using Web.API.Constants;
using Web.API.Features.Authentication.DTOs;
using Web.API.Features.Authentication.Models;
using Web.API.Features.Authentication.Results;
using Web.Shared.DTOs;

namespace Web.API.Features.Authentication.Services
{
    public interface IIdentityService
    {
        Task<IdentityResult> RegisterUserAsync(RegisterUserDTO model);
        Task<ApplicationUser> FindUserByIdAsync(string userId);
        Task<ApplicationUser> FindUserByEmailAsync(string email);
        Task<SignInResult> LoginAsync(LoginUserDTO model);
        Task<EmailConfirmationTokenResult> GenerateEmailConfirmationTokenAsync(string email);
        Task<IdentityResult> ConfirmEmailAsync(string userId, string token);
        Task<bool> IsEmailConfirmedAsync(ApplicationUser user);
        Task LogoutAsync();
        Task<IdentityResult> AddUserToRoleAsync(UserWithRoleDTO userWithRole);
        Task<IdentityResult> RemoveUserFromRoleAsync(UserWithRoleDTO userWithRole);
        Task<IList<Roles>> GetUserRolesAsync(ApplicationUser user);
    }
}