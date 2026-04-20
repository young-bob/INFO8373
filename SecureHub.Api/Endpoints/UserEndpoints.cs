using Microsoft.EntityFrameworkCore;
using SecureHub.Api.Data;
using SecureHub.Api.Security;
using System.Security.Claims;

namespace SecureHub.Api.Endpoints;

public static class UserEndpoints
{
    private static readonly string StorageDirectory = Path.Combine(Directory.GetCurrentDirectory(), "VaultStorage");

    public static void MapUserEndpoints(this IEndpointRouteBuilder app)
    {
        var group = app.MapGroup("/api/users").WithTags("User Settings").RequireAuthorization();

        // Security Phase 6: Right to Delete (GDPR)
        group.MapDelete("/me", async ([Microsoft.AspNetCore.Mvc.FromBody] DeleteAccountRequest req, HttpContext context, [Microsoft.AspNetCore.Mvc.FromServices] SecureHubDbContext db) =>
        {
            var userId = int.Parse(context.User.FindFirstValue(ClaimTypes.NameIdentifier)!);
            var user = await db.Users.Include(u => u.Files).FirstOrDefaultAsync(u => u.Id == userId);
            
            if (user == null || !PasswordHasher.VerifyPassword(req.Password, user.PasswordHash))
            {
                return Results.Unauthorized(); // Requires password confirmation
            }

            // Right to Erasure - delete physically all vault storage files
            foreach(var f in user.Files)
            {
               var physicalPath = Path.Combine(StorageDirectory, f.StorageFileName);
               if (File.Exists(physicalPath)) File.Delete(physicalPath);
            }

            db.Users.Remove(user); // EF Core CASCADE handles DB dependencies linking
            await db.SaveChangesAsync();

            context.Response.Cookies.Delete("SecureHubToken");

            return Results.Ok(new { Message = "Account and all data securely erased." });
        });
    }
}

public record DeleteAccountRequest(string Password);
