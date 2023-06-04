using CoreController;
using Entities.WS_USER.Response;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Threading.Tasks;
using USER_APP;

namespace ProjectVehicles.Controllers
{
    [Route("api/WS_US/[controller]")]
    [ApiController]
    public class VehicleController : UBaseController
    {
        [HttpPost("GetUserInfo")]
        public async Task<ActionResult<UserInfoDTO>> EmpresaList([FromBody] GetUserInfo.Ejecuta parametros)
        {
            if (!ModelState.IsValid)
            {
                return ValidationProblem();
            }
            return await Mediator.Send(parametros);
        }
    }
}
