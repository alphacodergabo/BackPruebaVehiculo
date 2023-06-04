
using System.Collections.Generic;

namespace Entities.WS_USER.Response
{
    public class UserInfoDTO
    {
        public string UserId { get; set; }
        public string Name { get; set; }
        public string LastName { get; set; }
        public string Doc { get; set; }
        public string DriverLicence { get; set; }
        public string PhoneNumber { get; set; }
        public string Mail { get; set; }
        public List<VehicleResponseDTO> Vehicles { get; set; }
    }
}
