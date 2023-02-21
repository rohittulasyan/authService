using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.AspNetCore.DataProtection.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using OpenIddict.EntityFrameworkCore.Models;
using System;
using Microsoft.AspNetCore.Identity;

namespace AuthService.Application.Models ;

public class ApplicationDbContext : IdentityUserContext<IdentityUser>
{
    public ApplicationDbContext(DbContextOptions options)
        : base(options)
    {
    }

}