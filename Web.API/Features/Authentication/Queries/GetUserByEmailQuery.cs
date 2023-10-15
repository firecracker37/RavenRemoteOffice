using Web.API.Features.Authentication.Models;
using Web.API.Features.Authentication.Services;
using Web.Shared.DTOs;

namespace Web.API.Features.Authentication.Queries
{
    public class GetUserByEmailQuery
    {
        private readonly IIdentityService _identityService;

        public GetUserByEmailQuery(
            IIdentityService identityService)
        {
            _identityService = identityService;
        }

        public async Task<ApplicationUser> ExecuteAsync(string email)
        {
            if (string.IsNullOrEmpty(email)) throw new ArgumentNullException(nameof(email));

            var user = await _identityService.FindUserByEmailAsync(email);

            if (user == null) return null;

            return user;
        }
    }
}
