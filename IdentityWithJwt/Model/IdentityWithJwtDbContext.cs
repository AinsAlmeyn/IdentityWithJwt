using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace IdentityWithJwt.Model
{
    public class IdentityWithJwtDbContext : IdentityDbContext
    {
        public IdentityWithJwtDbContext(DbContextOptions options) : base(options)
        {

        }
    }
}
