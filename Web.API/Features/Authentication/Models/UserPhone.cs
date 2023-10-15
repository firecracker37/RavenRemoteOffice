using System.ComponentModel.DataAnnotations.Schema;
using System.ComponentModel.DataAnnotations;

namespace Web.API.Features.Authentication.Models
{
    public class UserPhone
    {
        [Key]
        public int Id { get; set; }

        [StringLength(30, ErrorMessage = "Nickname cannot be longer than 30 characters.")]
        public string NickName { get; set; }

        [Required]
        [Phone(ErrorMessage = "Not a valid phone number.")]
        public string PhoneNumber { get; set; }

        [ForeignKey("UserProfile")]
        public int UserProfileId { get; set; }

        public UserProfile UserProfile { get; set; }
    }
}
