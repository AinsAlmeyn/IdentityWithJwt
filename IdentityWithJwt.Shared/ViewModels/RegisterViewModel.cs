using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace IdentityWithJwt.Shared.ViewModels
{
    public class RegisterViewModel
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; }

        [Required]
        [StringLength(50, MinimumLength = 8)]
        public string Password { get; set; }

        [Required]
        [StringLength(50, MinimumLength = 8)]
        [Compare(nameof(Password),ErrorMessage ="Sifreler eslesmiyor")]
        public string ConfirmPassword { get; set; }
    }
}
