using System.Diagnostics;
using Web.Shared.DTOs;

namespace Web.API.Features.Authentication.Services
{
    public class EmailServiceDummy : IEmailService
    {
        private readonly ILogger<EmailServiceDummy> _logger;

        public EmailServiceDummy(ILogger<EmailServiceDummy> logger)
        {
            _logger = logger;
        }

        public async Task SendEmailAsync(EmailDTO model)
        {
            if (model == null) throw new ArgumentNullException(nameof(model));

            // Construct the email content as HTML
            var emailContent = $@"
<html>
<head>
    <title>{model.Subject}</title>
</head>
<body>
    <p>To: {model.Email}</p>
    <p>Subject: {model.Subject}</p>
    <div>{model.Message}</div>
</body>
</html>";

            try
            {
                // Determine the project directory
                var projectDirectory = Directory.GetCurrentDirectory();

                // Ensure the /emails directory exists
                var emailsDirectory = Path.Combine(projectDirectory, "emails");
                Directory.CreateDirectory(emailsDirectory);

                // Write the email content to an HTML file in the /emails directory
                var filePath = Path.Combine(emailsDirectory, $"{Guid.NewGuid()}.html");
                await File.WriteAllTextAsync(filePath, emailContent);

                _logger.LogInformation($"Email content saved to: {filePath}");

                // Use the default web browser to open the HTML file
                Process.Start(new ProcessStartInfo
                {
                    FileName = "cmd",
                    Arguments = $"/c start {filePath}",
                    WindowStyle = ProcessWindowStyle.Hidden,
                    CreateNoWindow = true,
                    UseShellExecute = false
                });

                _logger.LogInformation("Email content opened in the default web browser.");
            }
            catch (Exception ex)
            {
                _logger.LogError($"Failed to open email content in the default web browser. Error: {ex.Message}");
            }
        }
    }
}
