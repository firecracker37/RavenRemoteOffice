using Microsoft.AspNetCore.Identity;
using System.Security.Claims;
using Web.API.Features.Authentication.DTOs;
using Web.API.Features.Authentication.Services;

public class AddUserToRoleCommand
{
    private readonly IIdentityService _identityService;
    private readonly IHttpContextAccessor _httpContextAccessor;

    public AddUserToRoleCommand(IIdentityService identityService, IHttpContextAccessor httpContextAccessor)
    {
        _identityService = identityService;
        _httpContextAccessor = httpContextAccessor;
    }

    public async Task<IdentityResult> ExecuteAsync(UserWithRoleDTO userWithRole)
    {
        if (userWithRole == null)
        {
            return IdentityResult.Failed(new IdentityError
            {
                Code = "NullUserWithRole",
                Description = $"{nameof(userWithRole)} cannot be null"
            });
        }

        if (userWithRole.User == null)
        {
            return IdentityResult.Failed(new IdentityError
            {
                Code = "NullUser",
                Description = $"{nameof(userWithRole.User)} cannot be null"
            });
        }

        if (string.IsNullOrEmpty(userWithRole.Role))
        {
            return IdentityResult.Failed(new IdentityError
            {
                Code = "NullRole",
                Description = $"{nameof(userWithRole.Role)} cannot be null"
            });
        }

        var currentUserId = _httpContextAccessor.HttpContext?.User?.FindFirstValue(ClaimTypes.NameIdentifier);
        if (currentUserId == null)
        {
            return IdentityResult.Failed(new IdentityError
            {
                Code = "Unauthorized",
                Description = "User is not authorized"
            });
        }

        var currentUser = await _identityService.FindUserByIdAsync(currentUserId);
        if (currentUser == null)
        {
            return IdentityResult.Failed(new IdentityError
            {
                Code = "UserNotFound",
                Description = "User is not found"
            });
        }

        var currentUserRoles = await _identityService.GetUserRolesAsync(currentUser);
        if (!currentUserRoles.Contains("Admin") && !currentUserRoles.Contains("Manager"))
        {
            return IdentityResult.Failed(new IdentityError
            {
                Code = "PermissionDenied",
                Description = "User does not have permission to assign roles"
            });
        }

        return await _identityService.AddUserToRoleAsync(userWithRole);
    }
}

