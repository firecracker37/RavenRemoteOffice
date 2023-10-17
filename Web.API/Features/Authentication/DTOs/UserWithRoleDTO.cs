using System.ComponentModel.DataAnnotations;
using Web.API.Features.Authentication.Models;

namespace Web.API.Features.Authentication.DTOs
{
    public class UserWithRoleDTO
    {
        [Required]
        public ApplicationUser User { get; set; }
        [Required]
        public string Role { get; set; }
    }
}
