using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Web.API.Features.Authentication.Models;
using Web.API.Features.Authentication.Services;
using Web.API.Infrastructure.DbContexts;
using Web.Shared.DTOs;

namespace Web.API.Features.Authentication.Commands
{
    public class RemoveUserAddressCommand
    {
        private readonly IIdentityService _identityService;
        private readonly ILogger<RemoveUserAddressCommand> _logger;
        private readonly ApplicationDbContext _dbContext;

        public RemoveUserAddressCommand(IIdentityService identityService, ILogger<RemoveUserAddressCommand> logger, ApplicationDbContext dbContext)
        {
            _identityService = identityService;
            _logger = logger;
            _dbContext = dbContext;
        }

        public async Task<IdentityResult> ExecuteAsync(ApplicationUser user, int addressId, UserAddressDTO model)
        {
            if (user == null || model == null || addressId <= 0)
                return IdentityResult.Failed(new IdentityError { Description = "An error occurred while processing your request." });

            // Check if the phone number belongs to the user
            var userAddress = await _dbContext.UserAddresses
                .FirstOrDefaultAsync(up => up.Id == model.Id && up.UserProfileId == user.UserProfileId);

            if (userAddress == null)
            {
                _logger.LogWarning($"User: {user.Email} does not own the address: {model.Id}");
                return IdentityResult.Failed(new IdentityError { Description = "You do not have permission to remove this phone number." });
            }

            // Call the IdentityService here to proceed with removing the phone number from the user.
            var result = await _identityService.RemoveUserAddressAsync(userAddress);

            return result;
        }
    }
}
