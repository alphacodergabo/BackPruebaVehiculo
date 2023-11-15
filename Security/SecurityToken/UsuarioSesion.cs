using Microsoft.AspNetCore.Http;
using Newtonsoft.Json;
using Security.SecurityToken.Contracts;
using System;
using System.Collections.Generic;
using System.Data;
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
        ValueJWT ClaimList = new ValueJWT();
        public ValueJWT ObtenerUsuarioSesion()
        {
            var userName = _httpContextAccesor.HttpContext.User?.Claims?.FirstOrDefault(x => x.Type == ClaimTypes.NameIdentifier)?.Value;
            var totalchaims = _httpContextAccesor.HttpContext.User?.Claims.ToList();
            var user = _httpContextAccesor.HttpContext.User;
            var claimsParsed = GetJWTFromCurrentUser(user);
            
            // foreach (var item in totalchaims)
            // {
            //     ClaimList.Add( new ClaimsValuesStore {
            //         TipoClaim = item.Type,
            //         Valor = item.Value
            //     });
            // }
            return claimsParsed;
        }

        public static ValueJWT GetJWTFromCurrentUser(ClaimsPrincipal claimsPrincipal)
        {
            ValueJWT jwt = null;
            if (claimsPrincipal != null)
            {
                var enumerator = claimsPrincipal.Claims.GetEnumerator();
                while (enumerator.MoveNext())
                {
                    var value = enumerator.Current.Value;
                    if (enumerator.Current.Type.Equals("dataUser"))
                    {
                        jwt = JsonConvert.DeserializeObject<ValueJWT>(value);
                    }
                }
            }
            return jwt;
        }
    }
    
}
