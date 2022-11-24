using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace IdentityWithJwt.Shared.ViewModels
{
    public class LoginViewModel
    {
        [Required(ErrorMessage ="Email adresi bos gecielemez")]
        [EmailAddress(ErrorMessage = "Gecersiz email adresi")]
        public string Email { get; set; }

        [Required(ErrorMessage = "Password alani bos gecilemez")]
        [StringLength(50,MinimumLength = 8, ErrorMessage = "Sifre 8-50 karakter araliginda olmali")]
        public string Password { get; set; }
    }
}
