using System;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Web.API.Features.Authentication.DTOs;
using Web.API.Features.Authentication.Results;
using Web.API.Features.Authentication.Services;
using Web.Shared.DTOs;

public class RequestPasswordResetCommand
{
    private readonly IIdentityService _identityService;
    private readonly IEmailService _emailService;
    private readonly IHttpContextAccessor _httpContextAccessor;

    public RequestPasswordResetCommand(
        IIdentityService identityService,
        IEmailService emailService,
        IHttpContextAccessor httpContextAccessor)
    {
        _identityService = identityService;
        _emailService = emailService;
        _httpContextAccessor = httpContextAccessor;
    }

    public async Task<EmailSendingResult> ExecuteAsync(string email)
    {
        if (string.IsNullOrEmpty(email))
            return new EmailSendingResult { Success = false, ErrorMessage = "Email was null or empty" };

        var user = await _identityService.FindUserByEmailAsync(email);

        if (user == null)
            return new EmailSendingResult { Success = false, ErrorMessage = "User not found" };

        var token = await _identityService.RequestPasswordResetAsync(user);

        if (string.IsNullOrEmpty(token))
            return new EmailSendingResult { Success = false, ErrorMessage = "Failed to generate password reset token" };

        // Construct the email content using EmailDTO
        var emailDTO = new EmailDTO
        {
            Email = email,
            Subject = "Reset Your Password",
            Message = $@"
        <table border='1'>
            <tr>
                <td><strong>User ID</strong></td>
                <td>{user.Id}</td>
            </tr>
            <tr>
                <td><strong>Password Reset Token</strong></td>
                <td>{Uri.EscapeDataString(token)}</td>
            </tr>
        </table>"
        };

        await _emailService.SendEmailAsync(emailDTO);

        return new EmailSendingResult { Success = true };
    }
}
