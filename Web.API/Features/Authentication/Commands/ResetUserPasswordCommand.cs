using Microsoft.AspNetCore.Identity;
using Web.API.Features.Authentication.Services;
using Web.Shared.DTOs;

namespace Web.API.Features.Authentication.Commands
{
    public class ResetUserPasswordCommand
    {
        private readonly IIdentityService _identityService;

        public ResetUserPasswordCommand(IIdentityService identityService)
        {
            _identityService = identityService;
        }

        public async Task<IdentityResult> ExecuteAsync(ResetUserPasswordDTO model)
        {
            if (model == null) return IdentityResult.Failed(new IdentityError { Description = "Model cannot be null" });

            if (string.IsNullOrEmpty(model.UserId) || string.IsNullOrEmpty(model.Token) || string.IsNullOrEmpty(model.Password))
                return IdentityResult.Failed(new IdentityError { Description = "User ID, Token, and Password are required" });

            // Call the ResetUserPasswordAsync method of the IdentityService
            var result = await _identityService.ResetUserPasswordAsync(model);

            return result;
        }
    }
}
