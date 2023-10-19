using AuthAPIs.Auth;
using AuthAPIs.Model.AuthDTOs;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Net.Mail;
using System.Net;
using System.Security.Claims;
using System.Text;
using System.Web;
using Microsoft.AspNetCore.Authorization;

namespace AuthAPIs.Controllers
{
    [Route("api/auth")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly JWTsettings _jwtSettings;
        private readonly IConfiguration _configuration;

        public AuthController(UserManager<ApplicationUser> userManager, JWTsettings jwtSettings, IConfiguration configuration) 
        {
            _userManager = userManager;
            _jwtSettings = jwtSettings;
            _configuration = configuration;
        }

        [HttpPost]
        [Route("login")]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        [ProducesResponseType(StatusCodes.Status401Unauthorized)]
        public async Task<IActionResult> Login([FromBody] LoginDTO loginDTO)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            try
            {
                ApplicationUser? user = await _userManager.FindByEmailAsync(loginDTO.Email);

                if (user == null)
                {
                    return Unauthorized();
                }

                if (!await _userManager.IsEmailConfirmedAsync(user))
                {
                    return BadRequest(new Auth.Response { Status = "Error", StatusMessage = "Email is not confirmed. Please confirm your email address before logging in." });
                }



                bool passwordIsValid = await _userManager.CheckPasswordAsync(user, loginDTO.Password);

                if (!passwordIsValid)
                {
                    return Unauthorized();
                }

                // add claims
                List<Claim> authClaims = new()
                {
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                    new Claim("UserId", user.Id)
                };

                // get roles
                IList<string> userRoles = await _userManager.GetRolesAsync(user);
                // add roles to claims
                foreach (string userRole in userRoles)
                {
                    authClaims.Add(new Claim(ClaimTypes.Role, userRole));
                }

                SymmetricSecurityKey securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtSettings.AccessTokenSecret));

                JwtSecurityToken token = new JwtSecurityToken(
                    issuer: _jwtSettings.Issuer,
                    audience: _jwtSettings.Audience,
                    expires: DateTime.Now.AddHours(3),
                    claims: authClaims,
                    signingCredentials: new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256)
                    );

                return Ok(new
                {
                    token = new JwtSecurityTokenHandler().WriteToken(token),
                    expiration = token.ValidTo,
                    roles = userRoles,
                    firstName = user.FirstName,
                    lastName = user.LastName,
                });
            }
            catch (Exception ex)
            {
                return BadRequest(ex.Message);
            }
        }

        [HttpPost]
        [Route("reg-client")]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        [ProducesResponseType(StatusCodes.Status500InternalServerError)]
        public async Task<IActionResult> RegClient([FromBody] SignUpDTO signupDTO)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            ApplicationUser? userExists;

            try
            {
                userExists = await _userManager.FindByEmailAsync(signupDTO.Email);

                if (userExists != null && await _userManager.IsEmailConfirmedAsync(userExists))
                {
                    return StatusCode(StatusCodes.Status500InternalServerError, new Auth.Response { Status = "Error", StatusMessage = "User with email address already registered" });
                }

                ApplicationUser applicationUser = new()
                {
                    FirstName = signupDTO.FirstName,
                    LastName = signupDTO.LastName,
                    Email = signupDTO.Email,
                    SecurityStamp = Guid.NewGuid().ToString(),
                    UserName = signupDTO.Email
                };

                if (signupDTO.PhoneNo != null)
                {
                    applicationUser.PhoneNumber = signupDTO.PhoneNo;
                }

                IdentityResult result = await _userManager.CreateAsync(applicationUser, signupDTO.Password);
                if (!result.Succeeded)
                {
                    return StatusCode(StatusCodes.Status500InternalServerError, new Auth.Response { Status = "Error", StatusMessage = "User creation failed! Please check user details and try again." });
                }

                await _userManager.AddToRoleAsync(applicationUser, UserRoles.Client);

                await SendActivationEmail(applicationUser, signupDTO.FirstName);

                return Ok(new Auth.Response { Status = "Success", StatusMessage = "User created successfully!" });
            }
            catch (Exception ex)
            {
                return BadRequest(ex.Message);
            }

        }
        private async Task SendActivationEmail(ApplicationUser user, string FirstName)
        {
            string token = await _userManager.GenerateEmailConfirmationTokenAsync(user);

            string? encodedUserId = HttpUtility.UrlEncode(user.Id);
            string? encodedToken = HttpUtility.UrlEncode(token);

            var callbackUrl = new Uri(Utils.Utilities.FrontEndLocation + "emailconf?user=" + encodedUserId + "&token=" + encodedToken);

            using SmtpClient smtpClient = new();
            smtpClient.Host = _configuration["EmailSettings:MailServer"];
            smtpClient.Port = Convert.ToInt32(_configuration["EmailSettings:MailPort"]);
            smtpClient.EnableSsl = true;
            smtpClient.Credentials = new NetworkCredential(
                _configuration["EmailSettings:MailUsername"],
                _configuration["EmailSettings:MailPassword"]
             );

            MailMessage message = new();
            message.To.Add(new MailAddress(user.Email));
            message.From = new MailAddress(_configuration["EmailSettings:MailFromAddress"]);
            message.Subject = "YOBMEK Account Confirmation";
            message.Body = "<html>" +
                "<body>" +
                "<h1>Hello " + FirstName + "</h1>" +
                "<p>Welcome this service.</p>" +
                "<p>Please confirm your account by clicking <a href=\"" + callbackUrl + "\">here</a></p>" +
                "</body>" +
                "</html>";
            message.IsBodyHtml = true;

            await smtpClient.SendMailAsync(message);
        }



        [HttpPost]
        [Route("confirmemail")]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        public async Task<ActionResult> ConfirmEmail(ConfirmEmailDTO confirmEmailDTO)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            try
            {
                ApplicationUser? user = await _userManager.FindByIdAsync(confirmEmailDTO.UserID);

                if (user == null)
                {
                    return NotFound();
                }

                IdentityResult result = await _userManager.ConfirmEmailAsync(user, confirmEmailDTO.Token);

                if (result.Succeeded)
                {
                    return Ok(new { Status = "Success", StatusMessage = "Email confirmed successfully" });
                }
                else
                {
                    return BadRequest();
                }
            }

            catch (Exception e)
            {
                return BadRequest(e.Message);
            }
        }



        [HttpPost]
        [Route("SendForgotPasswordLink")]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        public async Task<ActionResult> ForgotPassword([FromBody] ForgotPasswordDTO forgotPasswordDTO)
        {
            if (ModelState.IsValid)
            {
                var user = await _userManager.FindByEmailAsync(forgotPasswordDTO.Email);

                if (user == null)
                {
                    // User not found; don't reveal this information
                    return NotFound();
                }

                if (!await _userManager.IsEmailConfirmedAsync(user))
                {
                    // User's email is not confirmed; don't reveal this information
                    return NotFound();
                }

                string token = await _userManager.GeneratePasswordResetTokenAsync(user);

                DateTime expiryTime = DateTime.UtcNow.AddHours(1);

                string? encodedUserId = HttpUtility.UrlEncode(user.Id);

                string? encodedToken = HttpUtility.UrlEncode(token);
                //string? encodedEmail = HttpUtility.UrlEncode(model.Email);

                //var callbackUrl = new Uri(Utils.Utilities.FrontEndLocation + "emailconf?user=" + encodedUserId + "&token=" + encodedToken);
                //var callbackUrl = new Uri(Utils.Utilities.FrontEndLocation + "resetPass?user=" + encodedUserId + "&token=" + encodedToken + "&email=" + encodedEmail);
                var callbackUrl = new Uri(Utils.Utilities.FrontEndLocation + "resetPass?user=" + encodedUserId + "&token=" + encodedToken);

                // Save the token and expiry time in the database (you'll need to implement this)
                string? firstName = user.FirstName;


                try
                {
                    using SmtpClient smtpClient = new();
                    smtpClient.Host = _configuration["ForgotPasswordSettings:MailServer"];
                    smtpClient.Port = Convert.ToInt32(_configuration["ForgotPasswordSettings:MailPort"]);
                    smtpClient.EnableSsl = true;
                    smtpClient.Credentials = new NetworkCredential(
                        _configuration["ForgotPasswordSettings:MailUsername"],
                        _configuration["ForgotPasswordSettings:MailPassword"]
                     );

                    MailMessage message = new();
                    message.To.Add(new MailAddress(user.Email));
                    message.From = new MailAddress(_configuration["ForgotPasswordSettings:MailFromAddress"]);
                    message.Subject = "YObMEK Account Password Reset";
                    message.Body = "<html>" +
                        "<body>" +
                        "<h1>Hello " + firstName + "</h1>" +
                        "<p>Welcome to Kemboy portal services.</p>" +
                        "<p>To update your password click this link <a href=\"" + callbackUrl + "\">here</a></p>" +
                        "</body>" +
                        "</html>";
                    message.IsBodyHtml = true;

                    await smtpClient.SendMailAsync(message);

                    return Ok(new Auth.Response { Status = "success", StatusMessage = "Please Check Your Email to Reset Your Password" });
                }
                catch (Exception ex)
                {
                    return Ok(new Auth.Response { Status = "fail", StatusMessage = "Failed to send the email. Please try again later." + ex });
                }
            }

            return Ok(new Auth.Response { Status = "fail", StatusMessage = "System Error, Please Contact the Administrator" });
        }

        [Route("ResetPassword")]
        [HttpPost]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        [AllowAnonymous]
        public async Task<IActionResult> ResetPassword([FromBody] ForgotPasswordDTO forgotPasswordDTO)
        {
            if (ModelState.IsValid)

            {
                string decodedUserId = HttpUtility.UrlDecode(forgotPasswordDTO.UserId);
                string decodedToken = HttpUtility.UrlDecode(forgotPasswordDTO.Token);
                //string decodedEmail = HttpUtility.UrlDecode(forgotPasswordDTO.Email);
                var user = await _userManager.FindByIdAsync(decodedUserId);

                if (user == null)
                {
                    // User not found; don't reveal this information
                    return NotFound();
                }

                // Ensure that the provided password and confirm password match
                if (forgotPasswordDTO.Password != forgotPasswordDTO.ConfirmPassword)
                {
                    return Ok(new Auth.Response { Status = "fail", StatusMessage = "Password and Confirm Password do not match" });
                }

                // Reset the user's password

                var result = await _userManager.ResetPasswordAsync(user, decodedToken, forgotPasswordDTO.Password);

                if (result.Succeeded)
                {
                    return Ok(new Auth.Response { Status = "success", StatusMessage = "Password Reset Successfully. Proceed to Login" });
                }
                else
                {
                    // If there is an error during password reset, return the error message
                    return Ok(new Auth.Response { Status = "fail", StatusMessage = "Error Occurred during Password Reset. Please Contact the Administrator" });
                }

            }

            return Ok(new Auth.Response { Status = "fail", StatusMessage = "Wrong Input, Please Check Your Input and resend" });
         }



    }
}
