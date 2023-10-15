using System.ComponentModel.DataAnnotations;

namespace Web.Shared.DTOs
{
    public class EmailConfirmationDTO
    {
        [Required]
        public string UserId { get; set; }

        [Required]
        public string Token { get; set; }
    }
}
