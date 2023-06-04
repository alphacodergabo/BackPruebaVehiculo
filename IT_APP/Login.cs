using CoreController.Handlers;
using Domain;
using Entities.WS_IT.Response;
using FluentValidation;
using MediatR;
using Microsoft.AspNetCore.Identity;
using Security.SecurityToken.Contracts;
using System;
using System.Collections.Generic;
using System.Net;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace IT_APP
{
    public class Login
    {
        public class Ejecuta : IRequest<UserDataResponse>
        {
            public string UserName { get; set; }
            public string Password { get; set; }
        }

        public class EjecutaValidacion : AbstractValidator<Ejecuta>
        {
            public EjecutaValidacion()
            {
                RuleFor(x => x.UserName).NotEmpty().WithMessage("El usuario no debe estar Vacio").NotNull().WithMessage("El usuario no debe ser nulo");
                RuleFor(x => x.Password).NotEmpty().WithMessage("Debes Enviar un password");
            }
        }
        public class Manejador : IRequestHandler<Ejecuta, UserDataResponse>
        {
            private readonly UserManager<User> _userManager;
            private readonly SignInManager<User> _signInManager;
            private readonly IJwtGenerador _jwtGenerador;
            public Manejador(UserManager<User> userManager, SignInManager<User> signInManager, IJwtGenerador jwtGenerador)
            {
                _userManager = userManager;
                _signInManager = signInManager;
                _jwtGenerador = jwtGenerador;
            }
            public async Task<UserDataResponse> Handle(Ejecuta request, CancellationToken cancellationToken)
            {
                try
                {
                    var rp = new BasicResponse();
                    var user = await _userManager.FindByNameAsync(request.UserName);
                    if (user == null)
                    {
                        rp.MSG = "Usuario no existe";
                        rp.STATUS = false;
                        throw new ExceptionHandler(HttpStatusCode.Unauthorized, rp);
                    }
                    var resultado = await _signInManager.CheckPasswordSignInAsync(user, request.Password, false);
                    if (resultado.Succeeded)
                    {
                        return new UserDataResponse
                        {
                            UserId = user.Id,
                            NombreCompleto = user.Name + " " + user.LastName ,
                            Token = _jwtGenerador.CrearToken(user),
                            Username = user.UserName,
                            Email = user.Email
                        };
                    }
                    throw new ExceptionHandler(HttpStatusCode.Unauthorized);
                }
                catch (Exception e)
                {

                    throw new Exception(e.ToString());
                }
            }
        }
    }
}
