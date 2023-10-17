using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Web.Shared.DTOs
{
    public class ApplicationUserDTO
    {
        public string Id { get; set; }
        public UserProfileDTO UserProfile { get; set; }
    }
}
