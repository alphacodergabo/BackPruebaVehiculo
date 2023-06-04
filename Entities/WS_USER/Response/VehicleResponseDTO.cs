using System;
using System.Collections.Generic;
using System.Text;

namespace Entities.WS_USER.Response
{
    public class VehicleResponseDTO
    {
        public int VehicleId { get; set; }
        public string Brand { get; set; }
        public string Model { get; set; }
        public int Power { get; set; }
        public string Category { get; set; }
        public string Color { get; set; }
        public int DoorsPassenger { get; set; }
        public string RegistrationPlate { get; set; }
        public string Fuel { get; set; }
        public bool Active { get; set; }
    }
}
