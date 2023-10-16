using Microsoft.AspNetCore.Identity;
using Web.API.Features.Authentication.Services;
using Web.Shared.DTOs;

namespace Web.API.Features.Authentication.Commands
{
    public class RegisterCommand
    {
        private readonly IIdentityService _identityService;
        private readonly SendEmailVerificationEmailCommand _sendEmailVerificationEmailCommand;
        private readonly ILogger<RegisterCommand> _logger;

        public RegisterCommand(
            IIdentityService identityService, 
            SendEmailVerificationEmailCommand sendEmailVerificationEmailCommand,
            ILogger<RegisterCommand> logger)
        {
            _identityService = identityService;
            _sendEmailVerificationEmailCommand = sendEmailVerificationEmailCommand;
            _logger = logger;
        }

        public async Task<IdentityResult> ExecuteAsync(RegisterUserDTO model)
        {
            var result = await _identityService.RegisterUserAsync(model);

            if (result.Succeeded)
            {
                var emailResult = await _sendEmailVerificationEmailCommand.ExecuteAsync(model.Email);
                if (!emailResult.Success) _logger.LogWarning($"Unable to send email verification to {model.Email}. Message: {emailResult.ErrorMessage}");
            }
            return result;
        }
    }
}
