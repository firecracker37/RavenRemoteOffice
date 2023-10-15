using Web.API.Features.Authentication.Services;

namespace Web.API.Features.Authentication.Commands
{
    public class LogoutCommand
    {
        private readonly IIdentityService _identityService;

        public LogoutCommand(IIdentityService identityService)
        {
            _identityService = identityService;
        }

        public async Task ExecuteAsync()
        {
            await _identityService.LogoutAsync();
        }
    }
}
