using System.Security.Claims;
using System.Text.Json;
using AuthService.Application.Models;
using AuthService.Application.Models.DTO;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using OpenIddict.Abstractions;
using OpenIddict.EntityFrameworkCore.Models;
using OpenIddict.Server.AspNetCore;
using OpenIddict.Validation.AspNetCore;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace AuthService.Application.Controllers{

    

    public class ClientController : Controller {

        private readonly IServiceProvider _serviceProvider;
        private readonly IOpenIddictApplicationManager _applicationManager;
        private IOpenIddictAuthorizationManager _authorizationManager;
        private readonly UserManager<IdentityUser> _userManager;
        private readonly SignInManager<IdentityUser> _signInManager;
        private IOpenIddictTokenManager _tokenManager;
        private readonly IServiceScope _serviceScope;
        
        public ClientController(
            IServiceProvider serviceProvider,
            IOpenIddictApplicationManager applicationManager,
            IOpenIddictAuthorizationManager authorizationManager,
            IOpenIddictTokenManager tokenManager,
            UserManager<IdentityUser> userManager,
            SignInManager<IdentityUser> signInManager
        ) {
            
            _serviceProvider = serviceProvider;
            _applicationManager = applicationManager;
            _serviceScope = _serviceProvider.CreateScope();
            _userManager = userManager;
            _signInManager = signInManager;
            _tokenManager = tokenManager;
            _authorizationManager = authorizationManager;
        }
        
        // [Authorize]
        [HttpPost]
        [Route("api/createClient")]
        public async Task<IActionResult> createClient(CreateClientDTO  createClientDTO, CancellationToken cancellationToken)
        {   
            string jsonString =  JsonSerializer.Serialize(createClientDTO);
            Console.WriteLine("request: " + jsonString);

            if (await _applicationManager.FindByClientIdAsync(createClientDTO.ClientId, cancellationToken) == null)
            {

                await _applicationManager.CreateAsync(new OpenIddictApplicationDescriptor
                {
                    ClientId = createClientDTO.ClientId,
                    ClientSecret = createClientDTO.ClientSecret,
                    ConsentType = ConsentTypes.Explicit,
                    DisplayName = createClientDTO.ClientId.ToUpper(),
                    PostLogoutRedirectUris =
                    {
                        new Uri("https://example.com/signout-callback-oidc")
                    },
                    RedirectUris =
                    {
                        new Uri("https://example.com/signout-callback-oidc")
                    },
                    Permissions =
                    {
                        // Permissions.Endpoints.Authorization,
                        Permissions.Endpoints.Logout,
                        Permissions.Endpoints.Token,
                        Permissions.GrantTypes.Password,
                        Permissions.GrantTypes.RefreshToken,
                        Permissions.ResponseTypes.Code,
                        Permissions.Scopes.Email,
                        Permissions.Scopes.Profile,
                        Permissions.Scopes.Roles,
                        Permissions.Prefixes.Scope + "demo_api"
                    },
                    Requirements =
                    {
                        // Requirements.Features.ProofKeyForCodeExchange
                    }
                }, cancellationToken);

                return Ok("Client Create Succesfully'");
            }


            return Ok("Client Already Exists");
        }

        
        [HttpPost]
        [Route("api/signup")]
        public async Task<IActionResult> signUp(CreateUserDTO  createUserDTO, CancellationToken cancellationToken)
        {
            
            string jsonString =  JsonSerializer.Serialize(createUserDTO);
            Console.WriteLine("request: " + jsonString);
            
            IdentityUser user = new IdentityUser(
                userName: createUserDTO.Username
            );

            var result = await _userManager.CreateAsync(user, createUserDTO.Password);
            
            if(!result.Succeeded)
            {
                foreach (var error in result.Errors)
                {
                    Console.WriteLine(error.Code + error.Description);
                }
                
                return BadRequest(new AuthResult() {
                    Result = false,
                    Errors = new List<string>() { "Error while creating"}});
            }
            
            return Ok("User creation successsful");
        }
        
    
        

    } 

}