using System.ComponentModel.DataAnnotations;

namespace Web.Shared.DTOs
{
    public class EmailDTO
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; }
        [Required]
        public string Subject { get; set; }
        [Required]
        public string Message { get; set; }
    }
}
