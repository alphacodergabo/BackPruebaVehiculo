using Domain;
using Microsoft.AspNetCore.Identity;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Persistence
{
    public class CreateUser
    {
        public static async Task CreateUserMigration(AplicationContext context, UserManager<User> usuarioManager)
        {
            if (!usuarioManager.Users.Any())
            {
                var usuario = new User { Name = "Eduardo", LastName = "Ly", PhoneNumber="652620695", Doc="Y050345", DriverLicence="C",Active=true,RegistrationDate=DateTime.Now, UserName = "ely", Email = "gabo.9218@gmail.com" };
                await usuarioManager.CreateAsync(usuario, "Hola123456$");
            }
        }
    }
}
