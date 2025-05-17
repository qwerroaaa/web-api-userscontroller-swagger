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
                ModifiedBy = "System",
                RevokedOn = null
            });

            users.Add(new User
            {
                Guid = Guid.NewGuid(),
                Login = "User1",
                Password = "1",
                Name = "User",
                Gender = 1,
                Birthday = new DateTime(2005, 7, 20, 18, 30, 25),
                Admin = false,
                CreatedOn = DateTime.Now,
                CreatedBy = "System",
                ModifiedOn = DateTime.Now,
                ModifiedBy = "System",
                RevokedOn = null
            });
        }

        /// <summary>
        /// Get Token for Authorization. Login: Admin1; Password: 1
        /// </summary>
        [HttpPost("login")]
        public IActionResult Login([FromBody] LoginDTO dto)
        {
            var user = users.FirstOrDefault(u => u.Login == dto.Login && u.Password == dto.Password);
            if (user == null)
                return Unauthorized("Неверный логин или пароль.");

            if (user.RevokedOn != null)
                return BadRequest("Пользователь с такими данными заблокирован. Обратитесь к администратору");

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
        /// [NOT INCLUDE IN TASK] Get all users w/o conditions
        /// </summary>
        [HttpGet]
        public ActionResult<List<User>> GetAll() //вывод всех пользователей
        {
            return Ok(users);
        }


        /// <summary>
        /// [NOT INCLUDE IN TASK] Find a User by ID
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
                return Forbid("Только администратор может создать пользователя.");

            if (!Regex.IsMatch(dto.Login, "^[a-zA-Z0-9]+$") ||
                !Regex.IsMatch(dto.Password, "^[a-zA-Z0-9]+$") ||
                !Regex.IsMatch(dto.Name, "^[a-zA-Zа-яА-Я]+$"))
            {
                return BadRequest("Неверный ввод логина, пароля или имени.");
            }

            if (users.Any(u => u.Login == dto.Login))
            {
                return Conflict("Пользователь с таким логином уже существует.");
            }

            if (dto.Gender < 0 || dto.Gender > 2)
            {
                return BadRequest("Недопустимое значение для пола. Разрешены только 0, 1 или 2.");
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
                ModifiedBy = login,
                RevokedOn = null
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
        /// Update user info
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

            if(!Regex.IsMatch(dto.Name, "^[a-zA-Zа-яА-Я]+$"))
            {
                return BadRequest("Неверный ввод имени.");
            } else
            {
                userToUpdate.Name = dto.Name;
            }

            if (dto.Gender < 0 || dto.Gender > 2)
            {
                return BadRequest("Недопустимое значение для пола. Разрешены только 0, 1 или 2.");
            } else
            {
                userToUpdate.Gender = dto.Gender;
            }

            if (dto.Birthday.HasValue)
                userToUpdate.Birthday = dto.Birthday;

            userToUpdate.ModifiedOn = DateTime.Now;
            userToUpdate.ModifiedBy = jwtUser.Login;

            return Ok(userToUpdate);
        }

        /// <summary>
        /// Change user password
        /// </summary>
        [HttpPut("{login}/change-password")]
        public IActionResult ChangePassword(string login, [FromBody] ChangePasswordDTO dto)
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
                return Forbid("Нет прав на изменение пароля");

            if (string.IsNullOrWhiteSpace(dto.Password))
                return BadRequest("Пароль не может быть пустым");

            userToUpdate.Password = dto.Password;
            userToUpdate.ModifiedOn = DateTime.Now;
            userToUpdate.ModifiedBy = jwtUser.Login;

            return Ok("Пароль успешно изменён");
        }

        /// <summary>
        /// Change user login. Login must be unique.
        /// </summary>
        [HttpPut("{login}/change-login")]
        public IActionResult ChangeLogin(string login, [FromBody] ChangeLoginDTO dto)
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
                return Forbid("Нет прав на изменение логина");

            if (string.IsNullOrWhiteSpace(dto.Login))
                return BadRequest("Новый логин не может быть пустым");

            if (users.Any(u => u.Login == dto.Login && u.Guid != userToUpdate.Guid))
                return Conflict("Пользователь с таким логином уже существует");

            if (!Regex.IsMatch(dto.Login, "^[a-zA-Z0-9]+$")) 
            {
                return BadRequest("Неверный ввод логина.");
            }
            else
            {
                userToUpdate.Login = dto.Login;
            }
            userToUpdate.ModifiedOn = DateTime.Now;
            userToUpdate.ModifiedBy = jwtUser.Login;

            return Ok("Логин успешно изменён");
        }


        /// <summary>
        /// Get list of active users. Sorted by CreatedOn
        /// </summary>
        [HttpGet("active")]
        public IActionResult GetActiveUsers()
        {
            var jwtUser = GetCurrentUserFromToken(HttpContext);
            if (jwtUser == null)
                return Unauthorized("Невалидный токен");

            if(!jwtUser.Admin)
                return Forbid("Нет прав на просмотр. Нужны права администратора");

            var activeUsers = users.Where(u => u.RevokedOn == null).OrderBy(u => u.CreatedOn).ToList();

            return Ok(activeUsers);
        }

        /// <summary>
        /// Get list of users info. Read method number 6
        /// </summary>
        [HttpGet("{login}/userInfo")]
        public IActionResult GetInfoOfUsers(string login)
        {
            var jwtUser = GetCurrentUserFromToken(HttpContext);
            if (jwtUser == null)
                return Unauthorized("Невалидный токен");

            if (!jwtUser.Admin)
                return Forbid("Нет прав на просмотр. Нужны права администратора");

            var user = users.FirstOrDefault(u => u.Login == login);
            if (user == null)
                return NotFound("Пользователь не найден");

            var dto = new UserInfoDTO
            {
                Name = user.Name,
                Gender = user.Gender,
                Birthday = user.Birthday,
                Status = user.RevokedOn == null ? "Active" : "Revoked"
            };

            return Ok(dto);
        }

        /// <summary>
        /// Get user information(???????) by login and password
        /// </summary>
        [HttpPost("self")]
        public IActionResult GetSelfByLoginAndPassword([FromBody] LoginPasswordDTO dto)
        {
            var user = users.FirstOrDefault(u => u.Login == dto.Login && u.Password == dto.Password);
            if (user == null)
                return NotFound("Неверный логин или пароль");

            if (user.RevokedOn != null)
                return Forbid("Аккаунт заблокирован");

            var jwtUser = GetCurrentUserFromToken(HttpContext);
            if (jwtUser == null || jwtUser.Login != user.Login)
                return Forbid("Нет прав на просмотр. Только владелец может получить эти данные");

            return Ok(user);
        }

        /// <summary>
        /// Get all users who older than [age]
        /// </summary>
        [HttpGet("user-age/{age}")]
        public IActionResult GetAllUsersWhoOlderThanAgeNumber(int age)
        {
            var jwtUser = GetCurrentUserFromToken(HttpContext);
            if (jwtUser == null)
                return Unauthorized("Невалидный токен");

            if (!jwtUser.Admin)
                return Forbid("Нет прав на просмотр. Нужны права администратора");

            var today = DateTime.Today;
            var usersOlderThan = users
                .Where(u => u.Birthday.HasValue && (today.Year - u.Birthday.Value.Year -
                       (u.Birthday.Value.Date > today.AddYears(-age) ? 1 : 0)) > age)
                .ToList();

            return Ok(usersOlderThan);
        }

        /// <summary>
        /// Delete user full or soft. Full == true, soft == false
        /// </summary>
        [HttpDelete("{login}")]
        public IActionResult DeleteUser(string login, [FromBody] DeleteUserDTO dto)
        {
            var user = users.FirstOrDefault(u => u.Login == login);
            if (user == null)
                return NotFound("Пользователь не найден");

            var jwtUser = GetCurrentUserFromToken(HttpContext);
            if (jwtUser == null)
                return Unauthorized("Невалидный токен");

            if (!jwtUser.Admin)
                return Forbid("Доступ только для админа");

            if (dto.TypeDelete)
            {
                users.Remove(user);
                return Ok($"Пользователь {login} полностью удалён");
            } 
            else
            {
                if (user.RevokedOn != null)
                    return BadRequest("Пользователь уже удален");

                user.RevokedOn = DateTime.Now;
                user.RevokedBy = jwtUser.Login;

                return Ok($"Пользователь {login} мягко удалён");
            }
        }

        /// <summary>
        /// Restore user
        /// </summary>
        [HttpPut("restore/{login}")]
        public IActionResult RestoreUser(string login)
        {
            var user = users.FirstOrDefault(u => u.Login == login);
            if (user == null)
                return NotFound("Пользователь не найден");

            var jwtUser = GetCurrentUserFromToken(HttpContext);
            if (jwtUser == null)
                return Unauthorized("Невалидный токен");

            if (!jwtUser.Admin)
                return Forbid("Нет прав администратора");

            if (user.RevokedOn == null && string.IsNullOrEmpty(user.RevokedBy))
                return BadRequest("Пользователь уже активен");

            user.RevokedOn = null;
            user.RevokedBy = null;
            user.ModifiedOn = DateTime.Now;
            user.ModifiedBy = jwtUser.Login;

            return Ok($"Пользователь {login} успешно восстановлен");
        }
    }
}
