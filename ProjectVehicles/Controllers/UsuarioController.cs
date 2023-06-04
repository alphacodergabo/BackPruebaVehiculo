
using CoreController;
using Entities.WS_IT.Response;
using Entities.WS_USER.Response;
using IT_APP;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Threading.Tasks;
using USER_APP;

namespace ProjectVehicles.Controllers
{
    [Route("api/WS_IT/[controller]")]
    [ApiController]
    public class UsuarioController : UBaseController
    {
        [AllowAnonymous]
        [HttpPost("login")]
        public async Task<ActionResult<UserDataResponse>> Login([FromBody]  Login.Ejecuta parametros)
        {            
            if (!ModelState.IsValid)
            {
                return ValidationProblem();
            }
            return await Mediator.Send(parametros);
        }

    }
}
