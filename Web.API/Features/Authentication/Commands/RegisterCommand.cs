using Microsoft.AspNetCore.Identity;
using Web.API.Features.Authentication.Services;
using Web.Shared.DTOs;

namespace Web.API.Features.Authentication.Commands
{
    public class RegisterCommand
    {
        private readonly IIdentityService _identityService;

        public RegisterCommand(IIdentityService identityService)
        {
            _identityService = identityService;
        }

        public async Task<IdentityResult> ExecuteAsync(RegisterUserDTO model)
        {
            var result = await _identityService.RegisterUserAsync(model);
            return result;
        }
    }
}
