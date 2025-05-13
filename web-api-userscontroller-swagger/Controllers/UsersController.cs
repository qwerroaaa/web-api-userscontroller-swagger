using System.Security.Claims;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using web_api_userscontroller_swagger.DTO;
using web_api_userscontroller_swagger.Models;

namespace web_api_userscontroller_swagger.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class UsersController : ControllerBase
    {
        private static List<User> users = new();

        static UsersController() //register admin
        {
            users.Add(new User
            {
                Guid = Guid.NewGuid(),
                Login = "Admin777",
                Password = "password",
                Name = "Admin",
                Gender = 0,
                Birthday = null,
                Admin = true,
                CreatedOn = DateTime.Now,
                CreatedBy = "System",
                ModifiedOn = DateTime.Now,
                ModifiedBy = "System"
            });
        }

        [HttpPost("login")]
        public IActionResult Login([FromBody] LoginDTO dto)
        {
            var user = users.FirstOrDefault(u => u.Login == dto.Login && u.Password == dto.Password);
            if (user == null)
                return Unauthorized("Invalid credentials.");

            var tokenHandler = new System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes("a0b0605d01d04e41335a28aa47ec6ac4a4bdc2ebacf84f393846e217beb823c8");

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new[]
                {
                    new Claim(ClaimTypes.Name, user.Login),
                    new Claim("IsAdmin", user.Admin.ToString())
                }),
                Expires = DateTime.UtcNow.AddHours(1),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
            };

            var token = tokenHandler.CreateToken(tokenDescriptor);
            var jwt = tokenHandler.WriteToken(token);

            return Ok(new { token = jwt });
        }

        [HttpGet]
        public ActionResult<List<User>> GetAll()
        {
            return Ok(users);
        }

        [HttpGet("{guid}")]
        public ActionResult<User> GetByGuid(Guid guid) // ID search
        {
            var user = users.FirstOrDefault(u => u.Guid == guid);
            return user == null ? NotFound() : Ok(user);
        }

        [Authorize]
        [HttpPost]
        public ActionResult<User> CreateUser(CreateUserDTO dto)
        {
            var login = User.Identity?.Name;
            var isAdmin = User.Claims.FirstOrDefault(c => c.Type == "IsAdmin")?.Value == "True";

            //import JWT 
            if (!isAdmin)
                return Forbid("Only administrators can create users.");

            if (!Regex.IsMatch(dto.Login, "^[a-zA-Z0-9]+$") ||
                !Regex.IsMatch(dto.Password, "^[a-zA-Z0-9]+$") ||
                !Regex.IsMatch(dto.Name, "^[a-zA-Zа-яА-Я]+$"))
            {
                return BadRequest("Invalid input format.");
            }

            var user = new User
            {
                Guid = Guid.NewGuid(),
                Login = dto.Login,
                Password = dto.Password,
                Name = dto.Name,
                Gender = dto.Gender,
                Birthday = dto.Birthday,
                Admin = dto.Admin,
                CreatedOn = DateTime.UtcNow,
                CreatedBy = login,
                ModifiedOn = DateTime.UtcNow,
                ModifiedBy = login
            };

            users.Add(user);
            return CreatedAtAction(nameof(GetByGuid), new { guid = user.Guid }, user);
        }
    }
}
