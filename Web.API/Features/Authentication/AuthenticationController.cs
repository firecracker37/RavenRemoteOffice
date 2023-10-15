using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.ComponentModel.DataAnnotations;
using System.Security.Claims;
using Web.API.Constants;
using Web.API.Features.Authentication.Commands;
using Web.API.Features.Authentication.DTOs;
using Web.API.Features.Authentication.Models;
using Web.API.Features.Authentication.Queries;
using Web.Shared.DTOs;

namespace Web.API.Features.Authentication
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthenticationController : ControllerBase
    {
        private readonly IHttpContextAccessor _httpContextAccessor;
        private readonly RegisterCommand _registerCommand;
        private readonly LoginCommand _loginCommand;
        private readonly LogoutCommand _logoutCommand;
        private readonly SendEmailVerificationEmailCommand _sendEmailVerificationEmailCommand;
        private readonly VerifyUserEmailCommand _verifyUserEmailCommand;
        private readonly AddUserToRoleCommand _addUserToRoleCommand;
        private readonly RemoveUserFromRoleCommand _removeUserFromRoleCommand;
        private readonly GetUserQuery _getUserQuery;
        private readonly GetUserByEmailQuery _getUserByEmailQuery;
        private readonly ILogger<AuthenticationController> _logger;

        public AuthenticationController(
            IHttpContextAccessor httpContextAccessor,
            RegisterCommand registerCommand,
            LoginCommand loginCommand,
            LogoutCommand logoutCommand,
            SendEmailVerificationEmailCommand sendEmailVerificationEmailCommand,
            VerifyUserEmailCommand verifyUserEmailCommand,
            AddUserToRoleCommand addUserToRoleCommand,
            RemoveUserFromRoleCommand removeUserFromRoleCommand,
            GetUserQuery getUserQuery,
            GetUserByEmailQuery getUserByEmailQuery,
            ILogger<AuthenticationController> logger)
        {
            _httpContextAccessor = httpContextAccessor;
            _registerCommand = registerCommand;
            _loginCommand = loginCommand;
            _logoutCommand = logoutCommand;
            _sendEmailVerificationEmailCommand = sendEmailVerificationEmailCommand;
            _verifyUserEmailCommand = verifyUserEmailCommand;
            _addUserToRoleCommand = addUserToRoleCommand;
            _getUserQuery = getUserQuery;
            _getUserByEmailQuery = getUserByEmailQuery;
            _logger = logger;
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register(RegisterUserDTO model)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState); // Or handle validation errors as needed
            }

            var registerResult = await _registerCommand.ExecuteAsync(model);

            if (registerResult.Succeeded)
            {
                // Send the email confirmation
                var emailResult = await _sendEmailVerificationEmailCommand.ExecuteAsync(model.Email);

                if (emailResult.Success)
                {
                    // If email is sent successfully, return 201
                    return new StatusCodeResult(201);
                }
                else
                {
                    // Handle the case when the email sending fails, you can log this or handle it as per your requirement
                    return BadRequest("User registered, but failed to send the confirmation email.");
                }
            }
            else
            {
                return BadRequest(registerResult.Errors); // Or handle the error as needed
            }
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login(LoginUserDTO model)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            var result = await _loginCommand.ExecuteAsync(model);

            if (result.Succeeded)
            {
                return Ok();
            }
            else if (result.IsLockedOut)
            {
                return StatusCode(423);
            }
            else if (result.RequiresTwoFactor)
            {
                return StatusCode(449);
            }
            else if (result.EmailNotConfirmed)
            {
                return Unauthorized(new { message = "Email not confirmed" });
            }
            else
            {
                return Unauthorized();
            }
        }

        [HttpPost("logout")]
        public async Task<IActionResult> Logout()
        {
            await _logoutCommand.ExecuteAsync();
            return Ok("Logged out successfully.");
        }

        [HttpGet("confirm")]
        public async Task<IActionResult> ConfirmEmail([FromQuery] EmailConfirmationDTO model)
        {
            _logger.LogInformation($"ConfirmEmail called with UserId: {model.UserId}, Token: {model.Token}");

            if (!ModelState.IsValid)
            {
                _logger.LogError($"Model state for ConfirmEmail could not be confirmed. UserID: {model.UserId}, Token: {model.Token} ");
                return BadRequest(ModelState); // or handle validation errors as needed
            }

            var result = await _verifyUserEmailCommand.ExecuteAsync(model.UserId, model.Token);

            if (result.Succeeded)
            {
                _logger.LogInformation($"User with {model.UserId} has confirmed their Email");
                return Ok("Email confirmed successfully."); // or return another appropriate response
            }
            else
            {
                _logger.LogWarning($"Error occured while verifying email for user with ID: {model.UserId}");
                _logger.LogWarning(result.Errors.ToString());
                return BadRequest(result.Errors); // or handle the error as needed
            }
        }

        [HttpPost("resend-confirmation-email")]
        public async Task<IActionResult> ResendConfirmationEmail([FromBody] string email)
        {
            if (string.IsNullOrEmpty(email))
            {
                return BadRequest("Email is required.");
            }

            var result = await _sendEmailVerificationEmailCommand.ExecuteAsync(email);

            if (result.Success)
            {
                return Ok("Confirmation email re-sent successfully.");
            }
            else
            {
                return BadRequest(result.ErrorMessage);
            }
        }

        [HttpGet("{id}")]
        public async Task<ActionResult<ApplicationUser>> GetUser(string id)
        {
            var user = await _getUserQuery.ExecuteAsync(id);

            if (user == null) return NotFound();

            return Ok(user);
        }

        [HttpGet("email/{email}")]
        public async Task<ActionResult<ApplicationUser>> GetUserByEmail([EmailAddress] string email)
        {
            var user = await _getUserByEmailQuery.ExecuteAsync(email);

            if (user == null) return NotFound();

            return Ok(user);
        }

        [HttpGet("current")]
        [Authorize]
        public async Task<ActionResult<ApplicationUser>> GetCurrent()
        {
            var userId = _httpContextAccessor.HttpContext?.User?.FindFirstValue(ClaimTypes.NameIdentifier);

            if (string.IsNullOrEmpty(userId))
            {
                return Unauthorized(); // This should never happen if the user is authenticated
            }

            var user = await _getUserQuery.ExecuteAsync(userId);

            if (user == null) return NotFound();

            return Ok(user);
        }

        [HttpPost("role/add-user")]
        [Authorize(Roles = "Admin, Manager")]
        public async Task<ActionResult> AddUserToRole([EmailAddress] string email, string role)
        {
            var user = await _getUserByEmailQuery.ExecuteAsync(email);

            if (user == null) return NotFound();

            if (Enum.TryParse(role, true, out Roles roleEnum))
            {
                var result = await _addUserToRoleCommand.ExecuteAsync(new UserWithRoleDTO { User = user, Role = roleEnum });
                if (result.Succeeded) return Ok();
                return BadRequest(result);
            }
            else
            {
                return BadRequest("Invalid role");
            }
        }

        [HttpPost("role/remove-user")]
        [Authorize(Roles = "Admin, Manager")]
        public async Task<ActionResult> RemoveUserFromRole([EmailAddress] string email, string role)
        {
            var user = await _getUserByEmailQuery.ExecuteAsync(email);

            if (user == null) return NotFound();

            if (Enum.TryParse(role, true, out Roles roleEnum))
            {
                var result = await _removeUserFromRoleCommand.ExecuteAsync(new UserWithRoleDTO { User = user, Role = roleEnum });
                if (result.Succeeded) return Ok();
                return BadRequest(result);
            }
            else
            {
                return BadRequest("Invalid role");
            }
        }
    }
}
