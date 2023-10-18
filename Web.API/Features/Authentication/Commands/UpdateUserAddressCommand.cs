using Microsoft.AspNetCore.Identity;
using Web.API.Features.Authentication.Models;
using Web.API.Features.Authentication.Services;
using Web.API.Infrastructure.DbContexts;
using Web.Shared.DTOs;

namespace Web.API.Features.Authentication.Commands
{
    public class UpdateUserAddressCommand
    {
        private readonly IIdentityService _identityService;
        private readonly ILogger<UpdateUserAddressCommand> _logger;
        private readonly ApplicationDbContext _dbContext;

        public UpdateUserAddressCommand(IIdentityService identityService, ILogger<UpdateUserAddressCommand> logger, ApplicationDbContext dbContext)
        {
            _identityService = identityService;
            _logger = logger;
            _dbContext = dbContext;
        }

        public async Task<IdentityResult> ExecuteAsync(ApplicationUser user, int addressId, ManageUserAddressDTO model)
        {
            if (user == null || model == null || addressId <=0)
                return IdentityResult.Failed(new IdentityError { Description = "An error occurred while processing your request." });

            var userAddress = await _dbContext.UserAddresses.FindAsync(addressId);

            if (userAddress == null)
            {
                _logger.LogWarning($"Address with ID {addressId} not found for user: {user.Email}");
                return IdentityResult.Failed(new IdentityError { Description = "Address number not found." });
            }

            if (userAddress.UserProfileId != user.UserProfileId)
            {
                _logger.LogWarning($"User: {user.Email} does not own the address with ID {addressId}");
                return IdentityResult.Failed(new IdentityError { Description = "You do not have permission to update this address." });
            }

            // Map DTO to UserAddress
            userAddress.Street1 = model.Street1;
            userAddress.Street2 = model.Street2;
            userAddress.City = model.City;
            userAddress.State = model.State;
            userAddress.PostalCode = model.PostalCode;

            var updateResult = await _identityService.UpdateUserAddressAsync(userAddress);

            if (updateResult.Succeeded)
            {
                _logger.LogInformation($"Successfully updated address for user: {user.Email}");
            }
            else
            {
                _logger.LogError($"Failed to update address for user: {user.Email}. Errors: {string.Join(", ", updateResult.Errors.Select(e => e.Description))}");
            }

            return updateResult;
        }
    }
}
