using Microsoft.AspNetCore.Mvc;
using Web.API.Features.Authentication.Models;
using Web.Shared.DTOs;

namespace Web.API.Features.Authentication.Queries
{
    public class MapUserToDTOQuery
    {
        public ActionResult<ApplicationUserDTO> Execute(ApplicationUser user)
        {
            if (user == null)
            {
                return new NotFoundResult();
            }

            var userProfileDTO = new UserProfileDTO
            {
                Id = user.UserProfileId,
                FirstName = user.UserProfile.FirstName,
                LastName = user.UserProfile.LastName,
                Addresses = user.UserProfile.Addresses.Select(a => new UserAddressDTO
                {
                    Id = a.Id,
                    NickName = a.NickName,
                    Street1 = a.Street1,
                    Street2 = a.Street2,
                    City = a.City,
                    State = a.State,
                    PostalCode = a.PostalCode
                }).ToList(),
                PhoneNumbers = user.UserProfile.PhoneNumbers.Select(p => new UserPhoneDTO
                {
                    Id = p.Id,
                    NickName = p.NickName,
                    PhoneNumber = p.PhoneNumber
                }).ToList()
            };

            var userDTO = new ApplicationUserDTO
            {
                Id = user.Id,
                UserProfile = userProfileDTO
            };

            return new OkObjectResult(userDTO);
        }
    }
}
