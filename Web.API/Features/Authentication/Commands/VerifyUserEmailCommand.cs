using Microsoft.AspNetCore.Identity;
using Web.API.Features.Authentication.Services;

namespace Web.API.Features.Authentication.Commands
{
    public class VerifyUserEmailCommand
    {
        private readonly IIdentityService _identityService;
        
        public VerifyUserEmailCommand(
            IIdentityService identityService) 
        {
            _identityService = identityService;
        }

        public async Task<IdentityResult> ExecuteAsync(string userId, string token)
        {
            var result = await _identityService.ConfirmEmailAsync(userId, token);

            if(result.Succeeded)
            {
                // Perform any actions such as sending a welcome Email, setting database values, etc here if the email has been verified.
            }

            return result;
        }
    }
}
