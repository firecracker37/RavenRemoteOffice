using Microsoft.AspNetCore.Identity;
using Web.API.Features.Authentication.Results;
using Web.API.Features.Authentication.Services;
using Web.Shared.DTOs;

namespace Web.API.Features.Authentication.Commands
{
    public class LoginCommand
    {
        private readonly IIdentityService _identityService;

        public LoginCommand(
            IIdentityService identityService)
        {
            _identityService = identityService;
        }

        public async Task<LoginResult> ExecuteAsync(LoginUserDTO model)
        {
            var user = await _identityService.FindUserByEmailAsync(model.Email);
            if (user == null)
            {
                return new LoginResult { Succeeded = false };
            }

            if (!await _identityService.IsEmailConfirmedAsync(user))
            {
                return new LoginResult { EmailNotConfirmed = true };
            }

            var signInResult = await _identityService.LoginAsync(model);
            return new LoginResult
            {
                Succeeded = signInResult.Succeeded,
                IsLockedOut = signInResult.IsLockedOut,
                RequiresTwoFactor = signInResult.RequiresTwoFactor
            };
        }
    }
}
