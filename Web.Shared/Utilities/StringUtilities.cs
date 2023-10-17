namespace Web.Shared.Utilities
{
    public class StringUtilities
    {
        public static string SanitizePhoneNumber(string phoneNumber)
        {
            if (string.IsNullOrEmpty(phoneNumber))
                return null;

            // Removing all non-digit characters from the phone number
            return new string(phoneNumber.Where(c => char.IsDigit(c)).ToArray());
        }

        public static string FormatPhoneNumber(string sanitizedPhoneNumber)
        {
            if (sanitizedPhoneNumber == null || sanitizedPhoneNumber.Length != 10 || !sanitizedPhoneNumber.All(char.IsDigit))
                throw new FormatException("Invalid phone number format.");

            return long.TryParse(sanitizedPhoneNumber, out var phoneNumberAsLong)
                ? string.Format("{0:(###) ###-####}", phoneNumberAsLong)
                : throw new FormatException("Invalid phone number format.");
        }
    }
}
