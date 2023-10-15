using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

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
