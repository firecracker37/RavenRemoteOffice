using Web.API.Features.Authentication.Models;

namespace Web.API.Features.Authentication.Results
{
    public class LoginResult
    {
        public bool Succeeded { get; set; }
        public bool IsLockedOut { get; set; }
        public bool RequiresTwoFactor { get; set; }
        public bool EmailNotConfirmed { get; set; }
        public ApplicationUser User { get; set; }
    }
}
