using System;
using System.Collections.Generic;
using System.Text;

namespace Security.SecurityToken.Contracts
{
    public interface IUsuarioSesion
    {
        ValueJWT ObtenerUsuarioSesion();
    }
}
