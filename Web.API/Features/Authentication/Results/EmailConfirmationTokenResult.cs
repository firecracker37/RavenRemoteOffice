using Web.API.Features.Authentication.Models;

namespace Web.API.Features.Authentication.Results
{
    public class EmailConfirmationTokenResult
    {
        public bool Success { get; set; }
        public ApplicationUser User { get; set; }
        public string Token { get; set; }
        public string ErrorMessage { get; set; }
    }
}
