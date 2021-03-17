using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using LoginOAuth.Options;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;

namespace LoginOAuth.Controllers
{
    public class OAuthController : Controller
    {
        private readonly JwtSettings _jwtSettings;

        public OAuthController(JwtSettings jwtSettings)
        {
            _jwtSettings = jwtSettings;
        }

        [HttpGet]
        public IActionResult Authorize(
            string response_type,
            string client_id,
            string redirect_uri,
            string scope,
            string state)
        {
            var query = new QueryBuilder();
            query.Add("redirectUri", redirect_uri);
            query.Add("state", state);

            return View(model: query.ToString());
        }

        [HttpPost]
        public IActionResult Authorize(
            string username,
            string redirectUri,
            string state)
        {
            const string code = "asd";

            var query = new QueryBuilder();
            query.Add("code", code);
            query.Add("state", state);

            return Redirect($"{redirectUri}{query.ToString()}");
        }

        public object Token(
            string grant_type,
            string code,
            string redirect_uri,
            string client_id)
        {
            //mechanism to verify the code

            var tokenHandler = new JwtSecurityTokenHandler();
            var secretBytes = Encoding.ASCII.GetBytes(_jwtSettings.Secret);
            var key = new SymmetricSecurityKey(secretBytes);

            var authClaims = new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.Sub, "eu"),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim("granny", "cookie")
            };

            var tokenDescriptor = new SecurityTokenDescriptor()
            {
                Subject = new ClaimsIdentity(authClaims),

                Issuer = _jwtSettings.ValidIssuer,
                Audience = _jwtSettings.ValidAudience,

                Expires = DateTime.UtcNow.Add(_jwtSettings.TokenLifetime),

                SigningCredentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256Signature)
            };

            var token = tokenHandler.CreateToken(tokenDescriptor);
            var access_token = tokenHandler.WriteToken(token);

            var responseObj = new
            {
                access_token,
                token_type = "Bearer",
                raw_claim = "oauthTutorial"
            };

            return responseObj;
        }
    }
}