using Web.API.Features.Authentication.Services;
using Web.Shared.DTOs;

namespace Web.API.Features.Authentication.Queries
{
    public class GetUserQuery
    {
        private readonly IIdentityService _identityService;

        public GetUserQuery(
            IIdentityService identityService)
        {
            _identityService = identityService;
        }

        public async Task<UserInformationDTO> ExecuteAsync(string userId)
        {
            if (string.IsNullOrEmpty(userId)) throw new ArgumentNullException(nameof(userId));

            var user = await _identityService.FindUserByIdAsync(userId);

            if (user == null) return null;

            return new UserInformationDTO
            {
                Id = user.Id,
                Email = user.Email,
                FirstName = user.UserProfile.FirstName,
                LastName = user.UserProfile.LastName,
            };
        }
    }
}
