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
        private readonly GetUserRolesQuery _getUserRolesQuery;
        private readonly RequestPasswordResetCommand _requestPasswordResetCommand;
        private readonly ResetUserPasswordCommand _resetUserPasswordCommand;
        private readonly ChangeUserPasswordCommand _changeUserPasswordCommand;
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
            GetUserRolesQuery getUserRolesQuery,
            RequestPasswordResetCommand requestPasswordResetCommand,
            ResetUserPasswordCommand resetUserPasswordCommand,
            ChangeUserPasswordCommand changeUserPasswordCommand,
            ILogger<AuthenticationController> logger)
        {
            _httpContextAccessor = httpContextAccessor;
            _registerCommand = registerCommand;
            _loginCommand = loginCommand;
            _logoutCommand = logoutCommand;
            _sendEmailVerificationEmailCommand = sendEmailVerificationEmailCommand;
            _verifyUserEmailCommand = verifyUserEmailCommand;
            _addUserToRoleCommand = addUserToRoleCommand;
            _removeUserFromRoleCommand = removeUserFromRoleCommand;
            _getUserQuery = getUserQuery;
            _getUserByEmailQuery = getUserByEmailQuery;
            _getUserRolesQuery = getUserRolesQuery;
            _requestPasswordResetCommand = requestPasswordResetCommand;
            _resetUserPasswordCommand = resetUserPasswordCommand;
            _changeUserPasswordCommand = changeUserPasswordCommand;
            _logger = logger;
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register(RegisterUserDTO model)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            var registerResult = await _registerCommand.ExecuteAsync(model);

            if (registerResult.Succeeded)
            {
                return new StatusCodeResult(201);
            }
            else
            {
                return BadRequest(registerResult.Errors);
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
                return Ok("Email confirmed successfully.");
            }
            else
            {
                _logger.LogWarning($"Error occured while verifying email for user with ID: {model.UserId}");
                _logger.LogWarning(result.Errors.ToString());
                return BadRequest(result.Errors);
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

        [HttpPost("request-password-reset")]
        public async Task<IActionResult> RequestPasswordReset([FromBody] string email)
        {
            if (string.IsNullOrEmpty(email))
            {
                return BadRequest("Email is required.");
            }

            var result = await _requestPasswordResetCommand.ExecuteAsync(email);

            if (result.Success)
            {
                return Ok("Password reset email sent successfully.");
            }
            else
            {
                return BadRequest(result.ErrorMessage);
            }
        }
        [HttpPost("reset-user-password")]
        public async Task<IActionResult> ResetUserPassword([FromBody] ResetUserPasswordDTO model)
        {
            if (!ModelState.IsValid)
            {
                _logger.LogError("Model state for ResetUserPassword is invalid.");
                var errorMessages = ModelState.Values.SelectMany(v => v.Errors).Select(e => e.ErrorMessage);
                return BadRequest(new { Errors = errorMessages });
            }

            var result = await _resetUserPasswordCommand.ExecuteAsync(model);

            if (result.Succeeded) return Ok("Password reset successful");

            // Logging detailed error messages
            var errors = string.Join(", ", result.Errors.Select(e => e.Description));
            _logger.LogError($"Password reset failed for user ID {model.UserId}. Errors: {errors}");

            return BadRequest($"Password reset failed!");
        }
        [HttpGet("change-user-password")]
        [Authorize]
        public async Task<IActionResult> ChangeUserPassword([FromBody] ChangePasswordDTO model)
        {
            if (!ModelState.IsValid)
            {
                _logger.LogError("Model state for ChangeUserPassword is invalid.");
                var errorMessages = ModelState.Values.SelectMany(v => v.Errors).Select(e => e.ErrorMessage);
                return BadRequest(new { Errors = errorMessages });
            }

            var userId = _httpContextAccessor.HttpContext?.User?.FindFirstValue(ClaimTypes.NameIdentifier);

            if (string.IsNullOrEmpty(userId)) return Unauthorized();

            var user = await _getUserQuery.ExecuteAsync(userId);

            if (user == null) return NotFound();

            var result = await _changeUserPasswordCommand.ExecuteAsync(user, model);
            if (result.Succeeded) return Ok("Password changed successfully");

            // Logging detailed error messages
            var errors = string.Join(", ", result.Errors.Select(e => e.Description));
            _logger.LogError($"Password change failed for user ID {model.UserId}. Errors: {errors}");

            return BadRequest($"Password change failed!");
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
                return Unauthorized();
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

                var error = result.Errors.FirstOrDefault();

                if (error != null)
                {
                    switch (error.Code)
                    {
                        case "NullUserWithRole":
                        case "NullUser":
                        case "InvalidRole":
                            return BadRequest(error.Description);

                        case "Unauthorized":
                        case "UserNotFound":
                        case "PermissionDenied":
                            return Unauthorized(error.Description);

                        default:
                            return BadRequest("An unexpected error occurred");
                    }
                }
            }
            else
            {
                return BadRequest("Invalid role");
            }

            return BadRequest("An unexpected error occurred");
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

                var error = result.Errors.FirstOrDefault();

                if (error != null)
                {
                    switch (error.Code)
                    {
                        case "NullUserWithRole":
                        case "NullUser":
                        case "InvalidRole":
                            return BadRequest(error.Description);

                        case "Unauthorized":
                        case "UserNotFound":
                        case "PermissionDenied":
                            return Unauthorized(error.Description);

                        default:
                            return BadRequest("An unexpected error occurred");
                    }
                }
            }
            else
            {
                return BadRequest("Invalid role");
            }

            return BadRequest("An unexpected error occurred");
        }

        [HttpGet("role/get-user-roles")]
        [Authorize]
        public async Task<ActionResult> GetUserRoles([EmailAddress] string email)
        {
            if (string.IsNullOrEmpty(email)) return NotFound();

            var user = await _getUserByEmailQuery.ExecuteAsync(email);
            if (user == null) return NotFound();

            var userRoles = await _getUserRolesQuery.ExecuteAsync(user);

            if (userRoles == null || !userRoles.Any()) return NotFound("No roles assigned to the user");
            return Ok(userRoles);
        }

        [HttpGet("role/get-current-user-roles")]
        [Authorize]
        public async Task<ActionResult> GetCurrentUsersRoles()
        {
            var userId = _httpContextAccessor.HttpContext?.User?.FindFirstValue(ClaimTypes.NameIdentifier);
            if (string.IsNullOrEmpty(userId)) return Unauthorized("User is not logged in");

            var user = await _getUserQuery.ExecuteAsync(userId);
            if (user == null) return NotFound("User not found");

            var userRoles = await _getUserRolesQuery.ExecuteAsync(user);

            if (userRoles == null || !userRoles.Any()) return NotFound("No roles assigned to the user");
            return Ok(userRoles);
        }

    }
}
