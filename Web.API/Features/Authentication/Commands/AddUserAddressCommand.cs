using Microsoft.AspNetCore.Identity;
using Web.API.Features.Authentication.Models;
using Web.API.Features.Authentication.Services;
using Web.Shared.DTOs;

namespace Web.API.Features.Authentication.Commands
{
    public class AddUserAddressCommand
    {
        private readonly IIdentityService _identityService;
        private readonly ILogger<AddUserAddressCommand> _logger;

        public AddUserAddressCommand(IIdentityService identityService, ILogger<AddUserAddressCommand> logger)
        {
            _identityService = identityService;
            _logger = logger;
        }

        public async Task<IdentityResult> ExecuteAsync(ApplicationUser user, ManageUserAddressDTO model)
        {
            if (user == null || model == null)
                return IdentityResult.Failed(new IdentityError { Description = "An error occurred while processing your request." });

            var userAddress = new UserAddress
            {
                NickName = model.NickName,
                Street1 = model.Street1,
                Street2 = model.Street2,
                City = model.City,
                State = model.State,
                PostalCode = model.PostalCode,
                UserProfileId = user.UserProfileId,
                UserProfile = user.UserProfile
            };

            // Call the IdentityService here to proceed with adding the phone number to the user.
            var result = await _identityService.AddUserAddressAsync(user, userAddress);

            return result;
        }
    }
}
