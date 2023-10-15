using System.ComponentModel.DataAnnotations;

namespace Web.API.Features.Authentication.Models
{
    public class UserProfile
    {
        [Key]
        public int Id { get; set; }

        [Required]
        [StringLength(50, ErrorMessage = "First name cannot be longer than 50 characters.")]
        public string FirstName { get; set; }

        [Required]
        [StringLength(50, ErrorMessage = "Last name cannot be longer than 50 characters.")]
        public string LastName { get; set; }

        public virtual ICollection<UserAddress> Addresses { get; set; } = new List<UserAddress>();
        public virtual ICollection<UserPhone> PhoneNumbers { get; set; } = new List<UserPhone>();
    }
}
