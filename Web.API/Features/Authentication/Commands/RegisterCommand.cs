using Microsoft.AspNetCore.Identity;
using Web.API.Constants;
using Web.API.Features.Authentication.DTOs;
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
            // Register the user
            var registrationResult = await _identityService.RegisterUserAsync(model);

            if (registrationResult.Succeeded)
            {
                // Log if unable to send verification email
                var emailResult = await _sendEmailVerificationEmailCommand.ExecuteAsync(model.Email);
                if (!emailResult.Success)
                {
                    _logger.LogWarning($"Unable to send email verification to {model.Email}. Message: {emailResult.ErrorMessage}");
                }

                // Get the newly registered user
                var user = await _identityService.FindUserByEmailAsync(model.Email);

                // Check if the user retrieval was successful and user is not null
                if (user != null)
                {
                    // Create a UserWithRoleDTO object with the user and the Employee role
                    var userWithRole = new UserWithRoleDTO
                    {
                        User = user,
                        Role = Roles.Employee
                    };

                    // Add the user to the Employee role
                    var roleAssignmentResult = await _identityService.AddUserToRoleAsync(userWithRole);

                    // Optionally, log if unable to assign the role
                    if (!roleAssignmentResult.Succeeded)
                    {
                        _logger.LogWarning($"Unable to assign Employee role to {model.Email}. Errors: {string.Join(", ", roleAssignmentResult.Errors.Select(e => e.Description))}");
                    }
                }
                else
                {
                    _logger.LogWarning($"Unable to retrieve the user {model.Email} after registration.");
                }
            }

            return registrationResult;
        }

    }
}
