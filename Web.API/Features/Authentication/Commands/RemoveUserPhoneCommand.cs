using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Web.API.Features.Authentication.Models;
using Web.API.Features.Authentication.Services;
using Web.API.Infrastructure.DbContexts;
using Web.Shared.DTOs;
using Web.Shared.Utilities;

namespace Web.API.Features.Authentication.Commands
{
    public class RemoveUserPhoneCommand
    {
        private readonly IIdentityService _identityService;
        private readonly ILogger<RemoveUserPhoneCommand> _logger;
        private readonly ApplicationDbContext _dbContext;

        public RemoveUserPhoneCommand(
            IIdentityService identityService,
            ILogger<RemoveUserPhoneCommand> logger,
            ApplicationDbContext dbContext)
        {
            _identityService = identityService;
            _logger = logger;
            _dbContext = dbContext;
        }

        public async Task<IdentityResult> ExecuteAsync(ApplicationUser user, int phoneId, ManageUserPhoneDTO model)
        {
            if (user == null || model == null)
                return IdentityResult.Failed(new IdentityError { Description = "An error occurred while processing your request." });

            model.PhoneNumber = StringUtilities.SanitizePhoneNumber(model.PhoneNumber);

            if (string.IsNullOrEmpty(model.PhoneNumber) || model.PhoneNumber.Length < 10)
            {
                _logger.LogWarning($"Failed removing phone number for user: {user.Email} Phone Number: {model.PhoneNumber}");
                return IdentityResult.Failed(new IdentityError { Description = "Invalid phone number." });
            }

            // Check if the phone number belongs to the user
            var userPhone = await _dbContext.UserPhones
                .FirstOrDefaultAsync(up => up.Id == phoneId && up.UserProfileId == user.UserProfileId);

            if (userPhone == null)
            {
                _logger.LogWarning($"User: {user.Email} does not own the phone number: {model.PhoneNumber}");
                return IdentityResult.Failed(new IdentityError { Description = "You do not have permission to remove this phone number." });
            }

            // Call the IdentityService here to proceed with removing the phone number from the user.
            var result = await _identityService.RemoveUserPhoneNumberAsync(userPhone);

            return result;
        }
    }
}
