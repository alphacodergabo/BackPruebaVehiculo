using System;
using System.Collections.Generic;
using System.Text;

namespace Entities.WS_IT.Response
{
    public class UserDataResponse
    {
        public string UserId{ get; set; }
        public string NombreCompleto { get; set; }
        public string Token { get; set; }
        public string Email { get; set; }
        public string Username { get; set; }
    }
}
