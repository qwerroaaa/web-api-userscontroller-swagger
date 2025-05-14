using System;
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

        static UsersController() //register admin and test user
        {
            users.Add(new User
            {
                Guid = Guid.NewGuid(),
                Login = "Admin1",
                Password = "1",
                Name = "Admin",
                Gender = 0,
                Birthday = null,
                Admin = true,
                CreatedOn = DateTime.Now,
                CreatedBy = "System",
                ModifiedOn = DateTime.Now,
                ModifiedBy = "System"
            });

            users.Add(new User
            {
                Guid = Guid.NewGuid(),
                Login = "User1",
                Password = "1",
                Name = "User",
                Gender = 1,
                Birthday = null,
                Admin = false,
                CreatedOn = DateTime.Now,
                CreatedBy = "System",
                ModifiedOn = DateTime.Now,
                ModifiedBy = "System"
            });
        }

        /// <summary>
        /// Get Token for Authorization
        /// </summary>
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

        /// <summary>
        /// Get all users 
        /// </summary>
        [HttpGet]
        public ActionResult<List<User>> GetAll() //вывод всех пользователей
        {
            return Ok(users);
        }


        /// <summary>
        /// Find a User by ID
        /// </summary>
        [HttpGet("{guid}")]
        public ActionResult<User> GetByGuid(Guid guid) // ID search
        {
            var user = users.FirstOrDefault(u => u.Guid == guid);
            return user == null ? NotFound() : Ok(user);
        }

        /// <summary>
        /// Create a User by Admin
        /// </summary>
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

        private User? GetCurrentUserFromToken(HttpContext context)
        {
            var login = context.User.Identity?.Name;
            return users.FirstOrDefault(u => u.Login == login);
        }

        /// <summary>
        /// Update user info (admin or self)
        /// </summary>
        [HttpPut("{login}")]
        public IActionResult UpdateUserInfo (string login, [FromBody] UpdateUserDTO dto)
        {
            var userToUpdate = users.FirstOrDefault(u => u.Login == login);
            if (userToUpdate == null)
                return NotFound("Пользователь не найден");

            var jwtUser = GetCurrentUserFromToken(HttpContext);
            if (jwtUser == null)
                return Unauthorized("Невалидный токен");

            var isAdmin = jwtUser.Admin;
            var isSelf = jwtUser.Guid == userToUpdate.Guid;
            var isActive = userToUpdate.RevokedOn == null;

            if (!(isAdmin || (isSelf && isActive)))
                return Forbid("Нет прав на изменение этого пользователя");

            userToUpdate.Name = dto.Name;
            userToUpdate.Gender = dto.Gender;
            if (dto.Birthday.HasValue)
                userToUpdate.Birthday = dto.Birthday;

            userToUpdate.ModifiedOn = DateTime.Now;
            userToUpdate.ModifiedBy = jwtUser.Login;

            return Ok(userToUpdate);
        }
    }
}
