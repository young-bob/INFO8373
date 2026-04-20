using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using FluentValidation;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using SecureHub.Api.Data;
using SecureHub.Api.Models;
using SecureHub.Api.Security;

namespace SecureHub.Api.Endpoints;

public static class AuthEndpoints
{
    public static void MapAuthEndpoints(this IEndpointRouteBuilder app)
    {
        var group = app.MapGroup("/api/auth").WithTags("Authentication");

        group.MapPost("/register", async ([Microsoft.AspNetCore.Mvc.FromBody] RegisterRequest req, [Microsoft.AspNetCore.Mvc.FromServices] SecureHubDbContext db) =>
        {
            var validator = new RegisterRequestValidator();
            var result = await validator.ValidateAsync(req);
            if (!result.IsValid) 
                return Results.ValidationProblem(result.ToDictionary());

            if (await db.Users.AnyAsync(u => u.Email == req.Email))
            {
                // To prevent email enumeration attacks, you typically return a generic message.
                // However, the assignment requires "duplicate account prevention", so we return a clear bad request.
                return Results.BadRequest(new { Message = "Email already registered." });
            }

            var user = new User
            {
                Email = req.Email,
                PasswordHash = PasswordHasher.HashPassword(req.Password),
                Role = "User" // Default Role
            };

            db.Users.Add(user);
            await db.SaveChangesAsync();

            return Results.Ok(new { Message = "Registration successful." });
        });

        // 2.3: Brute Force Protection applied via 'RequireRateLimiting("LoginLimiter")'
        group.MapPost("/login", async ([Microsoft.AspNetCore.Mvc.FromBody] LoginRequest req, [Microsoft.AspNetCore.Mvc.FromServices] SecureHubDbContext db, HttpContext httpContext) =>
        {
            var user = await db.Users.SingleOrDefaultAsync(u => u.Email == req.Email);
            
            // Generic message for both incorrect email and password to prevent account enumeration
            if (user == null || !PasswordHasher.VerifyPassword(req.Password, user.PasswordHash))
            {
                return Results.Unauthorized(); 
            }

            var token = GenerateJwtToken(user);
            
            // Requirement 2.2: Secure Cookie flags
            var cookieOptions = new CookieOptions
            {
                HttpOnly = true,
                Secure = true, // Must be true in Production (forces HTTPS)
                SameSite = SameSiteMode.Strict,
                Expires = DateTime.UtcNow.AddMinutes(30) // Requirement 2.2: 30 minutes expiry
            };
            httpContext.Response.Cookies.Append("SecureHubToken", token, cookieOptions);

            return Results.Ok(new { 
                Message = "Login successful", 
                Role = user.Role, 
                Token = token // Provided for cross-origin clients (WASM) unable to read HttpOnly Cookies natively
            });
        }).RequireRateLimiting("LoginLimiter");
        
        group.MapPost("/logout", (HttpContext httpContext) =>
        {
            // Requirement 2.2: Logout invalidates session
            httpContext.Response.Cookies.Delete("SecureHubToken");
            return Results.Ok(new { Message = "Logout successful" });
        });
    }

    private static string GenerateJwtToken(User user)
    {
        var secret = Environment.GetEnvironmentVariable("JWT_SECRET");
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secret!));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        var claims = new[]
        {
            new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
            new Claim(ClaimTypes.Email, user.Email),
            new Claim(ClaimTypes.Role, user.Role),
            new Claim("Id", user.Id.ToString())
        };

        var token = new JwtSecurityToken(
            issuer: Environment.GetEnvironmentVariable("JWT_ISSUER"),
            audience: Environment.GetEnvironmentVariable("JWT_AUDIENCE"),
            claims: claims,
            expires: DateTime.UtcNow.AddMinutes(30),
            signingCredentials: creds
        );

        return new JwtSecurityTokenHandler().WriteToken(token);
    }
}

public record RegisterRequest(string Email, string Password);
public record LoginRequest(string Email, string Password);

public class RegisterRequestValidator : AbstractValidator<RegisterRequest>
{
    public RegisterRequestValidator()
    {
        RuleFor(x => x.Email).NotEmpty().EmailAddress().WithMessage("Valid email required.");
        
        // Requirement 2.1: Password strength validation
        RuleFor(x => x.Password)
            .NotEmpty()
            .MinimumLength(8)
            .Matches("[A-Z]").WithMessage("Password must contain at least one uppercase letter.")
            .Matches("[a-z]").WithMessage("Password must contain at least one lowercase letter.")
            .Matches("[0-9]").WithMessage("Password must contain at least one number.")
            .Matches("[^a-zA-Z0-9]").WithMessage("Password must contain at least one special character.");
    }
}
