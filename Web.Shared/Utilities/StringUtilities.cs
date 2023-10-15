using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Web.Shared.Utilities
{
    internal class StringUtilities
    {
        public static string SanitizePhoneNumber(string phoneNumber)
        {
            if (string.IsNullOrEmpty(phoneNumber))
                return null;

            // Removing all non-digit characters from the phone number
            return new string(phoneNumber.Where(c => char.IsDigit(c)).ToArray());
        }
    }
}
