using Microsoft.AspNetCore.Identity;
using System.Security.Claims;
using Web.API.Constants;
using Web.API.Features.Authentication.DTOs;
using Web.API.Features.Authentication.Services;

public class AddUserToRoleCommand
{
    private readonly IdentityService _identityService;
    private readonly IHttpContextAccessor _httpContextAccessor;

    public AddUserToRoleCommand(IdentityService identityService, IHttpContextAccessor httpContextAccessor)
    {
        _identityService = identityService;
        _httpContextAccessor = httpContextAccessor;
    }

    public async Task<IdentityResult> ExecuteAsync(UserWithRoleDTO userWithRole)
    {
        if (userWithRole == null) throw new ArgumentNullException(nameof(userWithRole));
        if (userWithRole.User == null) throw new ArgumentNullException(nameof(userWithRole.User));
        if (!Enum.IsDefined(typeof(Roles), userWithRole.Role))
            throw new ArgumentOutOfRangeException(nameof(userWithRole.Role), "Invalid role specified");

        var currentUserId = _httpContextAccessor.HttpContext?.User?.FindFirstValue(ClaimTypes.NameIdentifier);
        if (currentUserId == null)
        {
            throw new UnauthorizedAccessException("User is not authorized");
        }

        var currentUser = await _identityService.FindUserByIdAsync(currentUserId);
        if (currentUser == null)
        {
            throw new UnauthorizedAccessException("User is not found");
        }

        var currentUserRoles = await _identityService.GetUserRolesAsync(currentUser);
        if (!currentUserRoles.Contains(Roles.Admin) && !currentUserRoles.Contains(Roles.Manager))

        {
            throw new UnauthorizedAccessException("User does not have permission to assign roles");
        }

        return await _identityService.AddUserToRoleAsync(userWithRole);
    }
}
