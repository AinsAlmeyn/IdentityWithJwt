using IdentityWithJwt.Services;
using IdentityWithJwt.Shared.ViewModels;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using NuGet.DependencyResolver;

namespace IdentityWithJwt.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class ValuesController : ControllerBase
    {
        private IMailService _mailService;
        private IUserService _userService;
        private IConfiguration _configuration;

        public ValuesController(IUserService userService, IMailService mail, IConfiguration configuration)
        {
            _configuration = configuration;
            _mailService = mail;
            _userService = userService;
        }
        [HttpPost("Register")]
        public async Task<IActionResult> RegisterAsync([FromBody] RegisterViewModel model)
        {
            if (ModelState.IsValid)
            {
                var result = await _userService.RegisterUserAsync(model);
                if (result.IsSuccess)
                    return Ok(result);
            }
            return BadRequest("Invalid parameters");
        }

        [HttpPost("Login")]
        public async Task<IActionResult> LoginAsync([FromBody] LoginViewModel model)
        {
            if (ModelState.IsValid)
            {
                var result = await _userService.LoginUserAsync(model);
                if (result.IsSuccess)
                {
                    await _mailService.SendEmailAsync(model.Email, "Yeni Giris", "<h1>Giris Bildirimi<h1><p>Hesabiniza giris yapildi " + DateTime.Now + " </p>");
                    return Ok(result);
                }
                return BadRequest(result);
            }
            return BadRequest(model);
        }

        [HttpGet("ConfirmEmail")]
        public async Task<IActionResult> ConfirmEmail(string userId, string token)
        {
            if (string.IsNullOrWhiteSpace(userId) || string.IsNullOrWhiteSpace(token))
            {
                return BadRequest();
            }

            var result = await _userService.ConfirmEmailAsync(userId, token);
            if (result.IsSuccess)
            {
                return Redirect($"{_configuration["BaseUrl"]}/ConfirmEmail.html");
            }
            return BadRequest(result);
        }


        [HttpPost("ForgetPassword")]
        public async Task<IActionResult> ForgetPassword(string email)
        {
            if (string.IsNullOrEmpty(email))
            {
                return NotFound();
            }

            var result = await _userService.ForgetPasswordAsync(email);
            if (result.IsSuccess)
            {
                return Ok(result);
            }

            return BadRequest(result);
        }

        [HttpPost("ResetPassword")]
        public async Task<IActionResult> ResetPassword([FromForm] ResetPasswordViewModel model)
        {
            if (ModelState.IsValid)
            {
                var result = await _userService.ResetPasswordAsync(model);
                if (result.IsSuccess)
                {
                    return Ok(result);
                }
                return BadRequest(result);
            }
            return BadRequest("Bazi degerler yanlis girildi");
        }
    }
}
