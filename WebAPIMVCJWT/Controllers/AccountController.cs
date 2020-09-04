using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Claims;
using System.Web.Http;
using WebAPIMVCJWT;

namespace WebAPIJWT.Controllers
{
    public class AccountController : ApiController
    {

        [HttpGet]
        public HttpResponseMessage ValidLogin(string userName, string userPassword)
        {
            if (userName == "admin" && userPassword == "admin")
            {
                return Request.CreateResponse(HttpStatusCode.OK, TokenManager.GenerateToken(userName));
            }
            else {

                return Request.CreateResponse(HttpStatusCode.BadGateway, "Invlaid UserName or Password");
            }
        }

        [HttpGet]
        [CustomAuthenticationFilter]
        public HttpResponseMessage GetEmployee()
        {
                return Request.CreateResponse(HttpStatusCode.OK, "Successfully Valid");
        }
    }
}
