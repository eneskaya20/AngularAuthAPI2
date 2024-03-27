        using AngularAuthAPI.Context;
        using AngularAuthAPI.Helpers;
        using AngularAuthAPI.Models;
        using Microsoft.AspNetCore.Http;
        using Microsoft.AspNetCore.Mvc;
        using Microsoft.EntityFrameworkCore;
        using System.Security.Claims;
        using System.Text;
        using System.Text.RegularExpressions;
        using Microsoft.IdentityModel.Tokens;
        using System.IdentityModel.Tokens.Jwt;
        using Microsoft.AspNetCore.Authorization;

        namespace AngularAuthAPI.Controllers
        {
            [Route("api/[controller]")]
            [ApiController]
            public class UserController : ControllerBase
            {
                private readonly AppDbContext _authContext;
                public UserController(AppDbContext appDbContext)
                {
                    _authContext = appDbContext;
                }
                [HttpPost("authenticate")]
                public async Task<IActionResult> Authenticate([FromBody] User userObj)
                {
                    if (userObj == null)
                        return BadRequest();

                    var user = await _authContext.Users.FirstOrDefaultAsync(x => x.Username == userObj.Username);
                    if(user == null)
                        return NotFound(new {Message="User Not Found"});

                    if(!PasswordHasher.VerifyPassword(userObj.Password, user.Password))
                        return BadRequest(new { Message = "Password is Incorrect!" });

                    user.Token = CreateJWT(user);

                    return Ok(new
                    {
                        token = user.Token,
                        Message = "Login Successful!"
                    }); ;

                }


                [HttpPost("signup")]
                public async Task<IActionResult> SignupUser([FromBody] User userObj)
                {
                    if (userObj == null)
                        return BadRequest();
                    //check email
                    if (await CheckEmailExistAsync(userObj.Email))
                    {
                        return BadRequest(new { Message = "Email already exists!" });
                    }
                    // check username
                    if (await CheckUserNameExistAsync(userObj.Username))
                    {
                        return BadRequest(new { Message = "Username already exists!" });
                    }

                    // check password strength 
                    var pass = CheckPass
                wordStrength(userObj.Password);
                    if(!string.IsNullOrEmpty(pass))
                    {
                        return BadRequest(new { Message = pass.ToString() });
                    }   
                    userObj.Password = PasswordHasher.HashPassword(userObj.Password);
                    userObj.Role = "User";
                    userObj.Token = "";
                    await _authContext.Users.AddAsync(userObj);
                    await _authContext.SaveChangesAsync();
                    return Ok(new
                    {
                        Message = "User Signed Up Successfully!"
                    });
                }


                [HttpPost("register")]
                public async Task<IActionResult> RegisterUser([FromBody] User userObj)
                {
                    if (userObj == null)
                        return BadRequest();
                    //check email
                    if (await CheckEmailExistAsync(userObj.Email))
                    {
                        return BadRequest(new { Message = "Email already exists!" });
                    }
                    // check username
                    if (await CheckUserNameExistAsync(userObj.Username))
                    {
                        return BadRequest(new { Message = "Username already exists!" });
                    }

                    // check password strength 
                    var pass = CheckPasswordStrength(userObj.Password);
                    if (!string.IsNullOrEmpty(pass))
                    {
                        return BadRequest(new { Message = pass.ToString() });
                    }
                    userObj.Password = PasswordHasher.HashPassword(userObj.Password);
                    userObj.Token = "";
                    await _authContext.Users.AddAsync(userObj);
                    await _authContext.SaveChangesAsync();
                    return Ok(new
                    {
                        Message = "User Registered Successfully!"
                    });
                }

                [HttpPost("delete")]
                public async Task<IActionResult> DeleteUser([FromBody] User userObj)
                {
                    if (userObj == null || userObj.Id == 0)
                    {
                        return BadRequest(new { Message = "Invalid user object" });
                    }

                    var user = await _authContext.Users.FindAsync(userObj.Id);
                    if (user == null)
                    {
                        return NotFound(new { Message = "User not found" });
                    }

                    _authContext.Users.Remove(user);
                    await _authContext.SaveChangesAsync();

                    return Ok(new { Message = "User deleted successfully" });
                }






                private Task<bool> CheckEmailExistAsync(string email)
                    => _authContext.Users.AnyAsync(x => x.Email == email);
                private Task<bool> CheckUserNameExistAsync(string username)
                    => _authContext.Users.AnyAsync(x => x.Username == username);

                private string CheckPasswordStrength(string password)
                {
                    StringBuilder sb = new StringBuilder();
                    if (password.Length < 8)
                    {
                        sb.Append("Password length should be at least 8 characters" +Environment.NewLine);
                    }if(!(Regex.IsMatch(password, "[A-Z]") && Regex.IsMatch(password, "[A-Z]") && Regex.IsMatch(password, "[0-9]")))
                    {
                        sb.Append("Password should be alphanumeric" + Environment.NewLine);
                    }if(!Regex.IsMatch(password, "[<,>,@,!,(,),{,},\\[,\\],|,`,¬,¦,!,\\,\",£,$,%,^,&,*,\",<,>,:,;,#,~,_,-,+,=,@,]"))
                    {
                        sb.Append("Password should contain special character" + Environment.NewLine);
                    }
                    return sb.ToString();

                }

                private string CreateJWT(User user)
                {
                    var jwtTokenHandler = new JwtSecurityTokenHandler();
                    var key = Encoding.ASCII.GetBytes("veryverysecretkey...verrrryyyverrryyysecretone");
                    var identity = new ClaimsIdentity(new Claim[]
                    {
                        new Claim(ClaimTypes.Role, user.Role),
                        new Claim(ClaimTypes.Name, $"{user.Username}")
                    });
                    var credentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256);

                    var tokenDescriptor = new SecurityTokenDescriptor
                    {
                        Subject = identity,
                        Expires = DateTime.Now.AddDays(1),
                        SigningCredentials = credentials
                    };
                    var token = jwtTokenHandler.CreateToken(tokenDescriptor);
                    return jwtTokenHandler.WriteToken(token);


                }

                [Authorize]

                [HttpGet]
                public async Task<IActionResult> GetAllUsers()
                {

                    return Ok(await _authContext.Users.ToListAsync());
                }



            }
        }
