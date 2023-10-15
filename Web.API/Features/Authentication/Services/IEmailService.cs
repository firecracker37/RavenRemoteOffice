using Web.Shared.DTOs;
namespace Web.API.Features.Authentication.Services
{
    public interface IEmailService
    {
        Task SendEmailAsync(EmailDTO model);
    }
}
