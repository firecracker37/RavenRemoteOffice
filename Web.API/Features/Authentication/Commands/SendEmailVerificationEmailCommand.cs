using Web.API.Features.Authentication.Results;
using Web.API.Features.Authentication.Services;
using Web.Shared.DTOs;

namespace Web.API.Features.Authentication.Commands
{
    public class SendEmailVerificationEmailCommand
    {
        private readonly IIdentityService _identityService;
        private readonly IEmailService _emailService;
        private readonly IHttpContextAccessor _httpContextAccessor; // Injected to build URLs

        public SendEmailVerificationEmailCommand(
            IIdentityService identityService,
            IEmailService emailService,
            IHttpContextAccessor httpContextAccessor) // Added IHttpContextAccessor
        {
            _identityService = identityService;
            _emailService = emailService;
            _httpContextAccessor = httpContextAccessor;
        }

        public async Task<EmailSendingResult> ExecuteAsync(string email)
        {
            if (string.IsNullOrEmpty(email)) throw new ArgumentNullException(nameof(email));

            var user = await _identityService.FindUserByEmailAsync(email);

            if (user == null)
                return new EmailSendingResult { Success = false, ErrorMessage = "User not found" };

            if (await _identityService.IsEmailConfirmedAsync(user))
                return new EmailSendingResult { Success = false, ErrorMessage = "User email already verified" };

            var tokenResult = await _identityService.GenerateEmailConfirmationTokenAsync(email);

            if (!tokenResult.Success)
                return new EmailSendingResult { Success = false, ErrorMessage = tokenResult.ErrorMessage };

            // Construct the confirmation link
            var confirmationLink = _httpContextAccessor.HttpContext.Request.Scheme
                                   + "://" + _httpContextAccessor.HttpContext.Request.Host.Value
                                   + "/api/Authentication/confirm?userId=" + user.Id + "&token=" + Uri.EscapeDataString(tokenResult.Token);

            // Construct the email content using EmailDTO
            var emailDTO = new EmailDTO
            {
                Email = email,
                Subject = "Confirm Your Email",
                Message = $"Please confirm your account by <a href='{confirmationLink}'>clicking here</a>."
            };

            await _emailService.SendEmailAsync(emailDTO);

            return new EmailSendingResult { Success = true };
        }
    }
}
