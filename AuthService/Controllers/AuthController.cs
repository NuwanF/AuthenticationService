using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;

namespace AuthService.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : Controller
    {

        private IConfiguration _config;
        private readonly UserManager<IdentityUser> _userManager;
        private readonly SignInManager<IdentityUser> _signInManager;

        public AuthController(
            IConfiguration config,
            UserManager<IdentityUser> userManager,
            SignInManager<IdentityUser> signInManager
        )
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _config = config;
        }

        [Route("authenticateuser")]
        [AllowAnonymous]
        [HttpPost]
        public async Task<IActionResult> AuthenticateUser([FromBody]AuthenticateRequest request)
        {

            IActionResult response = Unauthorized();

            var loginStatus = await _signInManager.PasswordSignInAsync(request.Username, request.Password, true, false);
            if (!loginStatus.Succeeded)
            {
                throw new ArgumentException("Incorrect Credentials", "The user name or password is incorrect.");
            }

            var appUser = await _userManager.FindByEmailAsync(request.Username);

            var tokenString = GenerateJSONWebToken(appUser);
            response = Ok(new { token = tokenString });

            return response;
        }

        private string GenerateJSONWebToken(IdentityUser userInfo)
        {
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["Jwt:Key"]));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

            var claims = new[] {
                new Claim(JwtRegisteredClaimNames.Sub, userInfo.UserName),
                new Claim(JwtRegisteredClaimNames.Email, userInfo.Email),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            };

            var token = new JwtSecurityToken(_config["Jwt:Issuer"],
                _config["Jwt:Issuer"],
                claims,
                expires: DateTime.Now.AddMinutes(120),
                signingCredentials: credentials);

            return new JwtSecurityTokenHandler().WriteToken(token);
        }
    }

    public partial class AuthenticateRequest
    {
        public string Username { get; set; }
        public string Password { get; set; }
    }
}