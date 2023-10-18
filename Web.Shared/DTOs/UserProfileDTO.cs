namespace Web.Shared.DTOs
{
    public class UserProfileDTO
    {
        public int Id { get; set; }
        public string FirstName { get; set; }
        public string LastName { get; set; }
        public List<UserAddressDTO> Addresses { get; set; } = new List<UserAddressDTO>();
        public List<UserPhoneDTO> PhoneNumbers { get; set; } = new List<UserPhoneDTO>();
    }
}
