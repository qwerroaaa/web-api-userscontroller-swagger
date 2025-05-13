using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Mvc;
using web_api_userscontroller_swagger.DTO;
using web_api_userscontroller_swagger.Models;

namespace web_api_userscontroller_swagger.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class UsersController : ControllerBase
    {
        private static List<User> users = new();

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

        [HttpPost]
        public ActionResult<User> CreateUser(CreateUserDTO dto)
        {
            //import JWT 
            if (!IsAdmin)
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
                CreatedBy = currentUser,
                ModifiedOn = DateTime.UtcNow,
                ModifiedBy = currentUser
            };

            users.Add(user);
            return CreatedAtAction(nameof(GetByGuid), new { guid = user.Guid }, user);
        }
    }
}
