using System;
using System.Collections.Generic;
using System.Net;
using System.Text;

namespace CoreController.Handlers
{
    public class ExceptionHandler : Exception
    {
        public HttpStatusCode Codigo { get; }
        public object Errores { get; }
        public ExceptionHandler(HttpStatusCode codigo, object errores = null)
        {
            Codigo = codigo;
            Errores = errores;
        }
    }
}
