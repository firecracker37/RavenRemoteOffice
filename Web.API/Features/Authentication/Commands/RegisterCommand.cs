using Microsoft.AspNetCore.Identity;
using Web.API.Features.Authentication.Services;
using Web.Shared.DTOs;

namespace Web.API.Features.Authentication.Commands
{
    public class RegisterCommand
    {
        private readonly IIdentityService _identityService;
        private readonly SendEmailVerificationEmailCommand _sendEmailVerificationEmailCommand;

        public RegisterCommand(IIdentityService identityService, SendEmailVerificationEmailCommand sendEmailVerificationEmailCommand)
        {
            _identityService = identityService;
            _sendEmailVerificationEmailCommand = sendEmailVerificationEmailCommand;
        }

        public async Task<IdentityResult> ExecuteAsync(RegisterUserDTO model)
        {
            var result = await _identityService.RegisterUserAsync(model);

            if (result.Succeeded)
            {
                await _sendEmailVerificationEmailCommand.ExecuteAsync(model.Email);
            }
            return result;
        }
    }
}
