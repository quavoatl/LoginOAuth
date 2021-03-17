using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using LoginOAuth.Options;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;

namespace LoginOAuth.Controllers
{
    public class HomeController : Controller
    {
        private readonly JwtSettings _jwtSettings;

        public HomeController(JwtSettings jwtSettings)
        {
            _jwtSettings = jwtSettings;
        }

        public IActionResult Index()
        {
            return View();
        }

        [Authorize]
        public IActionResult Secret()
        {
            return View();
        }

        [HttpGet]
        public IActionResult Authenticate()
        {
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
            var tokenJson = tokenHandler.WriteToken(token);

            return Ok(new {access_token = tokenJson});
        }
    }
}