using IdentityWithJwt.Shared.Responses;
using IdentityWithJwt.Shared.ViewModels;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.CodeAnalysis.Emit;
using Microsoft.EntityFrameworkCore.Metadata.Internal;
using Microsoft.EntityFrameworkCore.Storage;
using Microsoft.EntityFrameworkCore.Storage.ValueConversion.Internal;
using Microsoft.IdentityModel.Tokens;
using SendGrid.Helpers.Errors.Model;
using System.IdentityModel.Tokens.Jwt;
using System.Runtime.CompilerServices;
using System.Security.Claims;
using System.Text;

namespace IdentityWithJwt.Services
{
    public interface IUserService
    {
        Task<UserManagerResponse> RegisterUserAsync(RegisterViewModel registerModel);
        Task<UserManagerResponse> LoginUserAsync(LoginViewModel loginModel);
        Task<UserManagerResponse> ConfirmEmailAsync(string userId, string token);
        Task<UserManagerResponse> ForgetPasswordAsync(string email);
        Task<UserManagerResponse> ResetPasswordAsync(ResetPasswordViewModel resetPasswordViewModel);
    }

    public class UserService : IUserService
    {
        private IMailService _mailService;
        private readonly UserManager<IdentityUser> _userManager;
        private IConfiguration _configuration;
        public UserService(UserManager<IdentityUser> userManager, IConfiguration configuration, IMailService mailService)
        {
            _configuration = configuration;
            _userManager = userManager;
            _mailService = mailService;
        }

        public async Task<UserManagerResponse> ConfirmEmailAsync(string userId, string token)
        {
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
                return new UserManagerResponse
                {
                    IsSuccess = false,
                    Message = "Kullanici bulunamadi"
                };

            var decodedToken = WebEncoders.Base64UrlDecode(token);
            string normalToken = Encoding.UTF8.GetString(decodedToken);

            var result = await _userManager.ConfirmEmailAsync(user, normalToken);
            if (result.Succeeded)
            {
                return new UserManagerResponse
                {
                    Message = "Email basariyla dogrulandi",
                    IsSuccess = true
                };
            }
            return new UserManagerResponse
            {
                IsSuccess = false,
                Message = "Email dogrulanamadi",
                Errors = result.Errors.Select(x => x.Description)
            };
        }

        public async Task<UserManagerResponse> LoginUserAsync(LoginViewModel loginModel)
        {

            #region Kullanici Var mi ?? Gecerli Mi
            var user = await _userManager.FindByEmailAsync(loginModel.Email);
            if (user == null)
            {
                return new UserManagerResponse
                {
                    Message = "Boyle bir kullanici bulunmamaktadir.",
                    IsSuccess = false
                };
            }
            var result = await _userManager.CheckPasswordAsync(user, loginModel.Password);
            if (!result)
            {
                return new UserManagerResponse
                {
                    Message = "Hatali sifre",
                    IsSuccess = false
                };
            }
            #endregion

            #region Token Olustur

            var claims = new[]
            {
                new Claim("Email",loginModel.Email),
                new Claim(ClaimTypes.NameIdentifier, user.Id)
            };

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["AuthenticationSettings:Key"]));
            var token = new JwtSecurityToken(
                issuer: _configuration["AuthenticationSettings:Issuer"],
                audience: _configuration["AuthenticationSettings:Audience"],
                claims: claims,
                expires: DateTime.Now.AddDays(1),
                signingCredentials: new SigningCredentials(key, SecurityAlgorithms.HmacSha256));
            string tokenToString = new JwtSecurityTokenHandler().WriteToken(token);

            return new UserManagerResponse
            {
                Message = tokenToString,
                IsSuccess = true,
                ExpireDate = token.ValidTo
            };
            #endregion

        }

        public async Task<UserManagerResponse> RegisterUserAsync(RegisterViewModel registerModel)
        {
            if (registerModel == null)
                throw new NullReferenceException("Kayit Modeli bos deger dondurdu.");

            IdentityUser identityUser = new()
            {
                Email = registerModel.Email,
                UserName = registerModel.Email
            };

            var result = await _userManager.CreateAsync(identityUser, registerModel.Password);

            if (result.Succeeded)
            {
                var confirmEamilToken = await _userManager.GenerateEmailConfirmationTokenAsync(identityUser);
                var encodedEmailToken = Encoding.UTF8.GetBytes(confirmEamilToken);
                var validEmailToken = WebEncoders.Base64UrlEncode(encodedEmailToken);
                string url = $"{_configuration["BaseUrl"]}/api/values/ConfirmEmail?userid={identityUser.Id}&token={validEmailToken}";
                await _mailService.SendEmailAsync(identityUser.Email, "Adresini Dogrula", "<h1>Demomuza Hosgeldiniz</h1> " + $" <p>Email adresinizi dogrulayin <a href='{url}'>Buraya Tikla</p>");
                

                return new UserManagerResponse
                {
                    Message = "Kullanici basariyla olusturuldu!",
                    IsSuccess = true
                };
            }
            return new UserManagerResponse
            {
                Message = "Kullanici olusturulamadi.",
                IsSuccess = false,
                Errors = result.Errors.Select(x => x.Description)
            };
        }

        public async Task<UserManagerResponse> ForgetPasswordAsync(string email)
        {
            var user = await _userManager.FindByEmailAsync(email);
            if (user == null)
                return new UserManagerResponse
                {
                    IsSuccess = false,
                    Message = "Bu email adresiyle bir kullanici bulunamadi"
                };

            var token = await _userManager.GeneratePasswordResetTokenAsync(user);
            var encodedToken = Encoding.UTF8.GetBytes(token);
            var validToken = WebEncoders.Base64UrlEncode(encodedToken);

            string url = $"{_configuration["BaseUrl"]}/ResetPassword?email={email}&token={validToken}";
            await _mailService.SendEmailAsync(email, "Sifreyi Sifirla", "<h1>Sifreyi sifirlamak icin talimatlari takip edin</h1> " + $"<p>Sifreyi sifirlamak icin tiklayin <a href='{url}'>Buraya Tikla</a></p>");

            return new UserManagerResponse
            {
                IsSuccess = true,
                Message = "Sifreyi sifirlama istegi basarili sekilde gonderildi."
            };
        }

        public async Task<UserManagerResponse> ResetPasswordAsync(ResetPasswordViewModel resetPasswordViewModel)
        {
            var user = await _userManager.FindByEmailAsync(resetPasswordViewModel.Email);
            if (user == null)
                return new UserManagerResponse
                {
                    IsSuccess = false,
                    Message = "Bu email adresiyle bir kullanici bulunamadi"
                };

            if (resetPasswordViewModel.NewPassword != resetPasswordViewModel.ConfirmPassword)
            {
                return new UserManagerResponse
                {
                    IsSuccess = false,
                    Message = "Sifreler eslesmiyor"
                };
            }

            var result = await _userManager.ResetPasswordAsync(user,resetPasswordViewModel.Token,resetPasswordViewModel.NewPassword);

            if (result.Succeeded)
                return new UserManagerResponse
                {
                    Message = "Sifre basariyla guncellendi",
                    IsSuccess = true
                };
            return new UserManagerResponse
            {
                Message = "Birseyler yanlis gitti",
                IsSuccess = false,
                Errors = result.Errors.Select(x => x.Description)
            };
        }
    }
}
