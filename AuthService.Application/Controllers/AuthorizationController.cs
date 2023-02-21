using AuthService.Application.Models;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text.Json;
using System.Threading.Tasks;
using static OpenIddict.Abstractions.OpenIddictConstants;
using OpenIddict.Server.AspNetCore;

namespace AuthService.Application.Controllers
{ 
    public class AuthorizationController : Controller
    {
                
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly UserManager<IdentityUser> _userManager;
        private readonly IConfiguration _iconfiguration;

        public AuthorizationController(
            UserManager<IdentityUser> userManager, 
            IConfiguration iconfiguration,
            SignInManager<IdentityUser> signInManager
        ){
            _signInManager = signInManager;
            _userManager = userManager;
        }
                
        [HttpPost("~/connect/token"), Produces("application/json")]
        public async Task<IActionResult> Exchange()

        {
            
            OpenIddictRequest request = HttpContext.GetOpenIddictServerRequest() ??
                                        throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");
                    
            string jsonString =  JsonSerializer.Serialize(request);
            Console.WriteLine("request: " + jsonString);
                    
            if (request.IsPasswordGrantType())
            {

                var user = await _userManager.FindByNameAsync(request.Username);
                        
                if (user == null) {
                    return  BadRequest( new AuthResult() {
                        Result = false,
                        Errors = new List<string>() { "Email does not exits."}
                    });
                }
                        
                var result = await _signInManager.CheckPasswordSignInAsync(user, request.Password, lockoutOnFailure: true);
                if (!result.Succeeded)
                    return BadRequest( new AuthResult() {
                        Result = false,
                        Errors = new List<string>() { "Wrong sign in  Password"}
                    });
                        

                var principal = await _signInManager.CreateUserPrincipalAsync(user);
                principal.SetClaim("key1", "Val1" );  
                principal.SetClaim("key2", "Val2" );


                principal.SetScopes(new[]
                {
                    Scopes.Phone,
                    Scopes.OpenId,
                    Scopes.Email,
                    Scopes.Profile,
                    Scopes.OfflineAccess,
                    Scopes.Roles,
                }.Intersect(request.GetScopes()));

                foreach (var claim in principal.Claims)
                {
                   
                    claim.SetDestinations(GetDestinations(claim, principal));
                }
                
               return SignIn(principal, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
            }


            if (request.IsRefreshTokenGrantType()) {
                
                // Retrieve the claims principal stored in the refresh token.
                var info = await HttpContext.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
                
                var user = await _userManager.GetUserAsync(info.Principal);
                if (user == null)
                    return Ok(Errors.InvalidToken +  "The refresh token is no longer valid.");

                // Ensure the user is still allowed to sign in.
                if (!await _signInManager.CanSignInAsync(user))
                    return Ok(Errors.InvalidGrant +  "The user is no longer allowed to sign in.");
                
                var principal = await _signInManager.CreateUserPrincipalAsync(user);

                foreach (var claim in principal.Claims)
                {
                    claim.SetDestinations(GetDestinations(claim, principal));
                }

                return SignIn(principal, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
            }


            throw new InvalidOperationException("The specified grant type is not supported.");
        }
        
        
        [Route("/connect/logout")]
        [HttpGet, HttpPost]
        public async Task<string> Logout()
        {
            bool before = _signInManager.IsSignedIn(HttpContext.User);
            
            // await _signInManager.SignOutAsync();
            // await _signInManager.SignOutAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);

            await HttpContext.SignOutAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
            // SignOut(  
            //     authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,  
            //     properties: new AuthenticationProperties  
            //     {  
            //         RedirectUri = "/"  
            //     });  

            bool after = _signInManager.IsSignedIn(User);


            return before.ToString() + "  " + after.ToString();
        }
        
        
        // [Route("/connect/logout")]
        // [HttpGet, HttpPost]
        // public async Task<string> Logout()
        // {
        //     //Get Bearer token
        //     string bearerToken = HttpContext.Request.Headers["Authorization"]
        //         .FirstOrDefault(header => header.StartsWith("Bearer "))?.Substring("Bearer ".Length);
        //     
        //     
        //     ClaimsPrincipal user = HttpContext.User;
        //     
        //     //Revoking by authorization id
        //     var auth_id = user.GetClaim("oi_au_id");
        //     
        //     await foreach (var token1 in  _tokenManager.FindByAuthorizationIdAsync(auth_id))
        //     {
        //         await _tokenManager.TryRevokeAsync(token1);
        //     }
        //    
        //     //Revoking by token Id
        //     // var token_id = user.GetClaim("oi_tkn_id");
        //     // var token = await _tokenManager.FindByIdAsync(token_id);
        //     // await _tokenManager.TryRevokeAsync(token);
        //
        //     return bearerToken;
        // }
        
        private IEnumerable<string> GetDestinations(Claim claim, ClaimsPrincipal principal)
        {   
            // Note: by default, claims are NOT automatically included in the access and identity tokens.
            // To allow OpenIddict to serialize them, you must attach them a destination, that specifies
            // whether they should be included in access tokens, in identity tokens or in both.
            Console.WriteLine(claim.Type);

            switch (claim.Type)
            {

                case Claims.Name:
                    yield return Destinations.AccessToken;

                    if (principal.HasScope(Scopes.Profile))
                        yield return Destinations.IdentityToken;

                    yield break;

                case Claims.PhoneNumber:
                    yield return Destinations.AccessToken;

                    if (principal.HasScope(Scopes.Phone))
                        yield return Destinations.IdentityToken;

                    yield break;

                case Claims.Role:
                    yield return Destinations.AccessToken;

                    if (principal.HasScope(Scopes.Roles))
                        yield return Destinations.IdentityToken;

                    yield break;

                case "dewdwe":
                    yield return Destinations.AccessToken;

                    // if (principal.HasScope(Scopes.Roles))
                    //     yield return Destinations.AccessToken;

                    yield break;

                // Never include the security stamp in the access and identity tokens, as it's a secret value.
                case "AspNet.Identity.SecurityStamp": yield break;

                default:
                    yield return Destinations.IdentityToken;
                    yield break;
            }
        }

            
    }
}