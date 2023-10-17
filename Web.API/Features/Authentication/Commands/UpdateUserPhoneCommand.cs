using Microsoft.AspNetCore.Identity;
using Web.API.Features.Authentication.Models;
using Web.API.Features.Authentication.Services;
using Web.API.Infrastructure.DbContexts;
using Web.Shared.DTOs;
using Web.Shared.Utilities;

namespace Web.API.Features.Authentication.Commands
{
    public class UpdateUserPhoneCommand
    {
        private readonly IIdentityService _identityService;
        private readonly ILogger<UpdateUserPhoneCommand> _logger;
        private readonly ApplicationDbContext _dbContext;

        public UpdateUserPhoneCommand(
            IIdentityService identityService, 
            ILogger<UpdateUserPhoneCommand> logger,
            ApplicationDbContext dbContext)
        {
            _identityService = identityService;
            _logger = logger;
            _dbContext = dbContext;
        }

        public async Task<IdentityResult> ExecuteAsync(ApplicationUser user, UserPhoneDTO model)
        {
            if (user == null || model == null)
                return IdentityResult.Failed(new IdentityError { Description = "An error occurred while processing your request." });

            if (model.Id == null)
            {
                _logger.LogWarning($"Failed updating phone number for user: {user.Email} as Phone ID is missing");
                return IdentityResult.Failed(new IdentityError { Description = "Phone ID is required for updating." });
            }

            model.PhoneNumber = StringUtilities.SanitizePhoneNumber(model.PhoneNumber);

            if (string.IsNullOrEmpty(model.PhoneNumber) || model.PhoneNumber.Length < 10)
            {
                _logger.LogWarning($"Failed updating phone number for user: {user.Email} Phone Number: {model.PhoneNumber}");
                return IdentityResult.Failed(new IdentityError { Description = "Invalid phone number." });
            }

            var userPhone = await _dbContext.UserPhones.FindAsync(model.Id);

            if (userPhone == null)
            {
                _logger.LogWarning($"Phone number with ID {model.Id} not found for user: {user.Email}");
                return IdentityResult.Failed(new IdentityError { Description = "Phone number not found." });
            }

            if (userPhone.UserProfileId != user.UserProfileId)
            {
                _logger.LogWarning($"User: {user.Email} does not own the phone number with ID {model.Id}");
                return IdentityResult.Failed(new IdentityError { Description = "You do not have permission to update this phone number." });
            }

            var updateResult = await _identityService.UpdateUserPhoneNumberAsync(userPhone, model);

            if (updateResult.Succeeded)
            {
                _logger.LogInformation($"Successfully updated phone number for user: {user.Email}");
            }
            else
            {
                _logger.LogError($"Failed to update phone number for user: {user.Email}. Errors: {string.Join(", ", updateResult.Errors.Select(e => e.Description))}");
            }

            return updateResult;
        }
    }
}
