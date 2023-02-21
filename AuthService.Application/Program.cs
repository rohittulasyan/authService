using OpenIddict.Validation.AspNetCore;
using AuthService.Application;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Identity;
using static OpenIddict.Abstractions.OpenIddictConstants;
using Quartz;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.OpenApi.Models;
using System.Reflection;
using AuthService.Application.Models;
using Microsoft.AspNetCore.Authorization;
using OpenIddict.Server.AspNetCore;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddDbContext<ApplicationDbContext>(options =>
{
    options.UseOpenIddict();
    options.UseSqlite(builder.Configuration.GetConnectionString("DefaultConnection"));

});

builder.Services.AddAuthentication(options =>
{
    options.DefaultScheme = OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme;
    
});


builder.Services.AddSwaggerGen(c =>
    {
        c.SwaggerDoc("v1", new OpenApiInfo { Title = "Auth Service", Version = "v1" });

        // Set the comments path for the Swagger JSON and UI.
        // string xmlFile = $"{Assembly.GetExecutingAssembly().GetName().Name}.xml";
        // string xmlPath = Path.Combine(AppContext.BaseDirectory, xmlFile);
        // c.IncludeXmlComments(xmlPath);

        //c.ExampleFilters();

        c.UseAllOfToExtendReferenceSchemas();

        c.AddSecurityDefinition("OpenID Connect", new OpenApiSecurityScheme
        {
            Type = SecuritySchemeType.OpenIdConnect,
            OpenIdConnectUrl = new Uri("/.well-known/openid-configuration", UriKind.Relative)
        });
    })
//.AddSwaggerExamplesFromAssemblyOf(typeof(VerifyInsuranceClaimCommandExample))
    ;


builder.Services
    .AddIdentityCore<IdentityUser>()
    // .AddRoles<IdentityRole>()
    .AddEntityFrameworkStores<ApplicationDbContext>()
    .AddDefaultTokenProviders()
    .AddDefaultUI();


builder.Services.Configure<IdentityOptions>(options =>
{
    // Configure Identity to use the same JWT claims as OpenIddict instead
    // of the legacy WS-Federation claims it uses by default (ClaimTypes),
    // which saves you from doing the mapping in your authorization controller.
    options.ClaimsIdentity.UserNameClaimType = Claims.Name;
    options.ClaimsIdentity.UserIdClaimType = Claims.Subject;
    options.ClaimsIdentity.RoleClaimType = Claims.Role;

    // Note: to require account confirmation before login,
    // register an email sender service (IEmailSender) and
    // set options.SignIn.RequireConfirmedAccount to true.
    //
    // For more information, visit https://aka.ms/aspaccountconf.
    options.SignIn.RequireConfirmedAccount = false;
});

// OpenIddict offers native integration with Quartz.NET to perform scheduled tasks
// (like pruning orphaned authorizations/tokens from the database) at regular intervals.
builder.Services.AddQuartz(options =>
{
    options.UseMicrosoftDependencyInjectionJobFactory();
    options.UseSimpleTypeLoader();
    options.UseInMemoryStore();
    
});

// Register the Quartz.NET service and configure it to block shutdown until jobs are complete.
builder.Services.AddQuartzHostedService(options => options.WaitForJobsToComplete = true);

builder.Services.AddOpenIddict()

    // Register the OpenIddict core components.
    .AddCore(options =>
    {
        // Configure OpenIddict to use the Entity Framework Core stores and models.
        // Note: call ReplaceDefaultEntities() to replace the default OpenIddict entities.
        options
            .UseEntityFrameworkCore()
            .UseDbContext<ApplicationDbContext>();
        
        // Enable Quartz.NET integration.
        options.UseQuartz();
    })

    // Register the OpenIddict server components.
    .AddServer(options =>
    {
        
        options
            // .AllowClientCredentialsFlow()
            .AllowPasswordFlow()
            .AllowRefreshTokenFlow();

        options.SetAccessTokenLifetime(TimeSpan.FromMinutes(60000));
        options.SetRefreshTokenLifetime(TimeSpan.FromHours(8000));
        options.SetRefreshTokenReuseLeeway(TimeSpan.Zero);

        options
            //.AllowAuthorizationCodeFlow()
            .RequireProofKeyForCodeExchange();

        options
            //.SetAuthorizationEndpointUris("/connect/authorize")
            .SetLogoutEndpointUris("/connect/logout")
            .SetTokenEndpointUris("/connect/token")
            .SetUserinfoEndpointUris("/connect/userinfo")
            ;

        // Encryption and signing of tokens
        options.UseDataProtection();
        
        // Register the signing and encryption credentials.
        options
            // .DisableAccessTokenEncryption()
            .AddDevelopmentEncryptionCertificate()
            .AddDevelopmentSigningCertificate();

        // Register scopes (permissions)
        options.RegisterScopes(Scopes.Email, Scopes.Profile, Scopes.Roles, Scopes.Phone);

        // Register the ASP.NET Core host and configure the ASP.NET Core-specific options.
        options
            .UseAspNetCore()
            .DisableTransportSecurityRequirement()
            //.EnableAuthorizationEndpointPassthrough()
            //.EnableUserinfoEndpointPassthrough()
            //.EnableStatusCodePagesIntegration()
            .EnableLogoutEndpointPassthrough()
            .EnableTokenEndpointPassthrough();

        // options.UseReferenceAccessTokens();
    })

    // Register the OpenIddict validation components.
    .AddValidation(options =>
    {
            
        // Import the configuration from the local OpenIddict server instance.
        options.UseLocalServer();

        //options.AddEncryptionKey(new SymmetricSecurityKey(
        //    Convert.FromBase64String("DRjd/GnduI3Efzen9V9BvbNUfc/VKgXltV7Kbk9sMkY=")));

        //// Register the System.Net.Http integration.
        //options.UseSystemNetHttp();

        // Register the ASP.NET Core host.
        options.UseAspNetCore();
            
        // Data protection
        options.UseDataProtection();
            

        // options.();
    });

// builder.Services.AddDataProtection()
//     .PersistKeysToDbContext<ApplicationDbContext>()
//     .SetApplicationName("heals-core");


// builder.Services.AddScoped<IIdentityStoresFactory, IdentityStoresFactory>();

// Register the worker responsible of seeding the database with the sample clients.
// Note: in a real world application, this step should be part of a setup script.
// builder.Services.AddHostedService<Worker>();

WebApplication app = builder.Build();

if (builder.Environment.IsDevelopment())
{
    app.UseDeveloperExceptionPage();
    app.UseMigrationsEndPoint();
    app.UseSwagger();
    app.UseSwaggerUI(c =>
    {
        c.SwaggerEndpoint("/swagger/v1/swagger.json", "Auth Service v1");
        ////c.EnableDeepLinking();

        ////// Additional OAuth settings (See https://github.com/swagger-api/swagger-ui/blob/v3.10.0/docs/usage/oauth2.md)
        //c.OAuthClientId("client-test-1");
        //c.OAuthClientSecret("388D45FA-B36B-4988-BA59-B187D329C207");
        ////c.OAuthAppName("test-app");
        ////c.OAuthScopeSeparator(" ");
        ////c.OAuthScopes("readAccess");
        //c.OAuthUsePkce();
    });
}

app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();

app.UseEndpoints(endpoints =>
{
    // endpoints.MapHealthChecks("/ready");
    // endpoints.MapHealthChecks("/healthz");

    endpoints.MapControllers();
    //endpoints.MapDefaultControllerRoute();
    //endpoints.MapRazorPages();
});

app.Run();