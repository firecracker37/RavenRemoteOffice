using Microsoft.AspNetCore.Identity;
using Web.API.Features.Authentication.Models;
using Web.API.Features.Authentication.Services;
using Web.Shared.DTOs;

namespace Web.API.Features.Authentication.Commands
{
    public class ChangeUserPasswordCommand
    {
        private readonly IIdentityService _identityService;

        public ChangeUserPasswordCommand(IIdentityService identityService)
        {
            _identityService = identityService;
        }

        public async Task<IdentityResult> ExecuteAsync(ApplicationUser user, ChangePasswordDTO model)
        {
            if (user == null) return IdentityResult.Failed(new IdentityError { Description = "The user was null or empty" });
            if (model == null) return IdentityResult.Failed(new IdentityError { Description = "The model was null or empty" });

            return await _identityService.ChangeUserPasswordAsync(user, model);
        }
    }
}
