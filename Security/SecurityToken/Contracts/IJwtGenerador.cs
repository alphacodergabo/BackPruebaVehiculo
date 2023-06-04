using Domain;
using System;
using System.Collections.Generic;
using System.Text;

namespace Security.SecurityToken.Contracts
{
    public interface IJwtGenerador
    {

        string CrearToken(User usuario);
    }
}
