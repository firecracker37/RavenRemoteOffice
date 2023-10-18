using System.ComponentModel.DataAnnotations;

namespace Web.Shared.DTOs
{
    public class ManageUserAddressDTO
    {
        [StringLength(30, ErrorMessage = "Nickname cannot be longer than 30 characters.")]
        public string NickName { get; set; }

        [Required]
        [StringLength(100, ErrorMessage = "Street address cannot be longer than 100 characters.")]
        public string Street1 { get; set; }

        [StringLength(100, ErrorMessage = "Street address cannot be longer than 100 characters.")]
        public string Street2 { get; set; }

        [Required]
        [StringLength(50, ErrorMessage = "City name cannot be longer than 50 characters.")]
        public string City { get; set; }

        [Required]
        [StringLength(2, MinimumLength = 2, ErrorMessage = "State must be a two-letter abbreviation.")]
        [RegularExpression(@"^[A-Z]{2}$", ErrorMessage = "State must be a two-letter abbreviation.")]
        public string State { get; set; }

        [Required]
        [StringLength(10, ErrorMessage = "Postal code cannot be longer than 10 characters.")]
        public string PostalCode { get; set; }
    }
}
