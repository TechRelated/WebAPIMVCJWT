using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading;
using System.Threading.Tasks;
using System.Web;
using System.Web.Http;
using System.Web.Http.Filters;
using System.Web.Http.Results;
using WebAPIJWT;

namespace WebAPIMVCJWT
{
    public class CustomAuthenticationFilter : AuthorizeAttribute, IAuthenticationFilter
    {
        public bool AllowMultiple { get { return false; } }
        public async Task AuthenticateAsync(HttpAuthenticationContext context, CancellationToken cancellationToken)
        {
            string authParameter = string.Empty;
            string[] TokenAndUser = null;

            HttpRequestMessage request = context.Request;

            AuthenticationHeaderValue authorization = request.Headers.Authorization;

            if(authorization == null)
            {
                context.ErrorResult = new AuthenticationFailureResult("missing Authorization header", request);
                return;
            }

            if (authorization.Scheme != "Bearer")
            {
                context.ErrorResult = new AuthenticationFailureResult("Invalid authorization scheme", request);
                return;
            }

            TokenAndUser = authorization.Parameter.Split(':');
            string Token = TokenAndUser[0];
            string userName = TokenAndUser[0];

            if (string.IsNullOrEmpty(Token))
            {
                context.ErrorResult = new AuthenticationFailureResult("Missing toekn", request);
                return;
            }

            string ValidUserName = TokenManager.ValidateToken(Token);

            if(userName != ValidUserName)
            {
                context.ErrorResult = new AuthenticationFailureResult("Invalid toekn for User", request);
                return;
            }

            context.Principal =  TokenManager.GetPrincipal(Token);
        }
        public class AuthenticationFailureResult : IHttpActionResult
        {
            public string ReasonPhrase;
            public HttpRequestMessage Request { get; set; }

            public AuthenticationFailureResult (string reasonPhrase, HttpRequestMessage request)
            {
                ReasonPhrase = reasonPhrase;
                Request = request;
            }

            public Task<HttpResponseMessage> ExecuteAsync(CancellationToken cancellationToken)
            {
                return Task.FromResult(Execute());
            }
            public HttpResponseMessage Execute()
            {
                HttpResponseMessage responseMessage = new HttpResponseMessage(System.Net.HttpStatusCode.Unauthorized);
                responseMessage.RequestMessage  = Request;
                responseMessage.ReasonPhrase = ReasonPhrase;
                return responseMessage;
            }
        }

        public async Task ChallengeAsync(HttpAuthenticationChallengeContext context, CancellationToken cancellationToken)
        {
            var result = await context.Result.ExecuteAsync(cancellationToken);
            if (result.StatusCode == System.Net.HttpStatusCode.Unauthorized) {

                result.Headers.WwwAuthenticate.Add(new AuthenticationHeaderValue("Basic", "realm=localhost"));                
            }

            context.Result = new ResponseMessageResult (result);
        }
    }
}