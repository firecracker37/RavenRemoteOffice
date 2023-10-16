using System.Security.Principal;
using Web.API.Constants;
using Web.API.Features.Authentication.Models;
using Web.API.Features.Authentication.Services;

namespace Web.API.Features.Authentication.Queries
{
    public class GetUserRolesQuery
    {
        private readonly IIdentityService _identityService;

        public GetUserRolesQuery(IIdentityService identityService)
        {
            _identityService = identityService;
        }

        public async Task<IList<Roles>> ExecuteAsync(ApplicationUser user)
        {
            if (user == null) return new List<Roles>();

            var roleList = await _identityService.GetUserRolesAsync(user);
            return roleList;
        }
    }
}
