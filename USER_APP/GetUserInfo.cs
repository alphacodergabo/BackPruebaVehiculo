using Domain;
using Entities.WS_USER.Response;
using FluentValidation;
using MediatR;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Persistence;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace USER_APP
{
    public class GetUserInfo
    {
        public class Ejecuta : IRequest<UserInfoDTO>
        {
            public string UserId{ get; set; }
        }
        public class EjecutaValidacion : AbstractValidator<Ejecuta>
        {
            public EjecutaValidacion()
            {
                RuleFor(x => x.UserId).NotEmpty().WithMessage("Debes Enviar un Id de usuario");
            }
        }
        public class Manejado : IRequestHandler<Ejecuta, UserInfoDTO>
        {
            private readonly AplicationContext _context;
            public Manejado(AplicationContext context)
            {
                _context = context;
            }
            public async Task<UserInfoDTO> Handle(Ejecuta request, CancellationToken cancellationToken)
            {
                try
                {
                    var user = await _context.User.FirstOrDefaultAsync(x => x.Id == request.UserId);
                    var Result = await _context.User.Select(
                        x => new UserInfoDTO
                        {
                            UserId = x.Id,
                            DriverLicence = x.DriverLicence,
                            LastName = x.LastName,
                            Mail = x.Email,
                            Name = x.Name,
                            Doc = x.Doc,
                            PhoneNumber = x.PhoneNumber,
                            Vehicles = x.Vehicle.
                            Select(y =>
                                new VehicleResponseDTO
                                {
                                    Brand = y.Brand,
                                    DoorsPassenger = y.DoorsPassenger,
                                    Active = y.Active,
                                    Category = y.Category,
                                    Color = y.Color,
                                    Model = y.Model,
                                    Power = y.Power,
                                    RegistrationPlate = y.RegistrationPlate,
                                    Fuel = y.Fuel,
                                    VehicleId = y.VehicleId
                                }).ToList()
                        }).FirstOrDefaultAsync(x => x.UserId == request.UserId);
                        


                    return (UserInfoDTO)Result;

                }
                catch (Exception e)
                {

                    throw new Exception(e.ToString());
                }
            }
        }
    }
}
