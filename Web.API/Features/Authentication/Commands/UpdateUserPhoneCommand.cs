using Microsoft.AspNetCore.Identity;
using Web.API.Features.Authentication.Models;
using Web.API.Features.Authentication.Services;
using Web.API.Infrastructure.DbContexts;
using Web.Shared.DTOs;

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

        public async Task<IdentityResult> ExecuteAsync(ApplicationUser user, int phoneId, ManageUserPhoneDTO model)
        {
            if (user == null || model == null)
                return IdentityResult.Failed(new IdentityError { Description = "An error occurred while processing your request." });

            if (phoneId <= 0)
                return IdentityResult.Failed(new IdentityError { Description = "Invalid phone number ID." });

            // Retrieve the UserPhone object using the phoneId
            var numberToUpdate = user.UserProfile.PhoneNumbers.FirstOrDefault(p => p.Id == phoneId);
            if (numberToUpdate == null)
                return IdentityResult.Failed(new IdentityError { Description = "Phone number not found." });

            // Update the UserPhone object with the new data from the DTO
            numberToUpdate.NickName = model.NickName;
            numberToUpdate.PhoneNumber = model.PhoneNumber;

            // Call the service to update the entity in the database
            var result = await _identityService.UpdateUserPhoneNumberAsync(numberToUpdate);

            return result;
        }
    }
}
