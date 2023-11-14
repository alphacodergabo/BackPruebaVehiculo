using Microsoft.AspNetCore.Http;
using Security.SecurityToken.Contracts;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;

namespace Security.SecurityToken
{
    public class UsuarioSesion : IUsuarioSesion
    {
        private readonly IHttpContextAccessor _httpContextAccesor;
        public UsuarioSesion(IHttpContextAccessor httpContextAccesor)
        {
            _httpContextAccesor = httpContextAccesor;
        }
        public string ObtenerUsuarioSesion()
        {
            var userName = _httpContextAccesor.HttpContext.User?.Claims?.FirstOrDefault(x => x.Type == ClaimTypes.NameIdentifier)?.Value;
            return userName;
        }
    }
}
