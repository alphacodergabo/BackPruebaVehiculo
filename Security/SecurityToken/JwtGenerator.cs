using Domain;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using Security.SecurityToken.Contracts;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace Security.SecurityToken
{
    public class JwtGenerator : IJwtGenerador
    {
        private readonly IConfiguration _configuration;
        public JwtGenerator(IConfiguration configuration)
        {
            _configuration = configuration;
        }
        public string CrearToken(User usuario)
        {
            string encryptionKid = _configuration["secretKey"];
            var claims = new List<Claim>(){
                new Claim("UserId", usuario.Id),
                new Claim(JwtRegisteredClaimNames.NameId, usuario.UserName),
                new Claim(JwtRegisteredClaimNames.Sub, usuario.Email),
                new Claim(JwtRegisteredClaimNames.UniqueName, usuario.Name + " " + usuario.LastName)
            };
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(encryptionKid.ToString()));
            var credenciales = new SigningCredentials(key, SecurityAlgorithms.HmacSha512Signature);
            var tokenDescripcion = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(claims),
                Expires = DateTime.Now.AddDays(2),
                SigningCredentials = credenciales
            };
            var tokenManejador = new JwtSecurityTokenHandler();
            var token = tokenManejador.CreateToken(tokenDescripcion);
            return tokenManejador.WriteToken(token);
        }
    }
}
