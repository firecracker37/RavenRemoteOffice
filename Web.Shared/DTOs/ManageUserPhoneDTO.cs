using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Web.Shared.DTOs
{
    public class ManageUserPhoneDTO
    {
        [StringLength(30, ErrorMessage = "Nickname cannot be longer than 30 characters.")]
        public string NickName { get; set; }

        [Required]
        [Phone(ErrorMessage = "Not a valid phone number.")]
        public string PhoneNumber { get; set; }
    }
}
