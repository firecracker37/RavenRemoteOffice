using Microsoft.AspNetCore.Identity;
using System.ComponentModel.DataAnnotations.Schema;
using System.ComponentModel.DataAnnotations;

namespace Web.API.Features.Authentication.Models
{
    public class ApplicationUser : IdentityUser
    {
        [Required]
        [ForeignKey("UserProfile")]
        public int UserProfileId { get; set; }

        public UserProfile UserProfile { get; set; }
    }
}
