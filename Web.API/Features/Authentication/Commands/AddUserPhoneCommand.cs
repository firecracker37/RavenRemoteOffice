﻿using Microsoft.AspNetCore.Identity;
using Web.API.Features.Authentication.Models;
using Web.API.Features.Authentication.Services;
using Web.Shared.DTOs;
using Web.Shared.Utilities;

namespace Web.API.Features.Authentication.Commands
{
    public class AddUserPhoneCommand
    {
        private readonly IIdentityService _identityService;
        private readonly ILogger<AddUserPhoneCommand> _logger;

        public AddUserPhoneCommand(IIdentityService identityService, ILogger<AddUserPhoneCommand> logger)
        {
            _identityService = identityService;
            _logger = logger;
        }

        public async Task<IdentityResult> ExecuteAsync(ApplicationUser user, ManageUserPhoneDTO model)
        {
            if (user == null || model == null)
                return IdentityResult.Failed(new IdentityError { Description = "An error occurred while processing your request." });

            model.PhoneNumber = StringUtilities.SanitizePhoneNumber(model.PhoneNumber);

            if (string.IsNullOrEmpty(model.PhoneNumber) || model.PhoneNumber.Length < 10)
            {
                _logger.LogWarning($"Failed adding phone number for user: {user.Email} Phone Number: {model.PhoneNumber}");
                return IdentityResult.Failed(new IdentityError { Description = "Invalid phone number." });
            }

            // Creating the UserPhone object in the command layer
            var userPhone = new UserPhone
            {
                NickName = model.NickName,
                PhoneNumber = model.PhoneNumber,
                UserProfileId = user.UserProfileId,
                UserProfile = user.UserProfile
            };

            // Call the IdentityService with the UserPhone object
            var result = await _identityService.AddUserPhoneNumberAsync(user, userPhone);

            return result;
        }
    }
}
