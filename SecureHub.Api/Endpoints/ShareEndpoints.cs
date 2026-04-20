using Microsoft.EntityFrameworkCore;
using SecureHub.Api.Data;
using SecureHub.Api.Models;
using SecureHub.Api.Security;
using System.Security.Claims;

namespace SecureHub.Api.Endpoints;

public static class ShareEndpoints
{
    private static readonly string StorageDirectory = Path.Combine(Directory.GetCurrentDirectory(), "VaultStorage");

    public static void MapShareEndpoints(this IEndpointRouteBuilder app)
    {
        var group = app.MapGroup("/api/shares").WithTags("File Sharing");

        // CREATE LINK
        group.MapPost("/", async ([Microsoft.AspNetCore.Mvc.FromBody] CreateShareRequest req, HttpContext context, [Microsoft.AspNetCore.Mvc.FromServices] SecureHubDbContext db) =>
        {
            var userIdStr = context.User.FindFirstValue(ClaimTypes.NameIdentifier);
            if (!int.TryParse(userIdStr, out var userId)) return Results.Unauthorized();

            // Task 4.2: IDOR Protection
            var file = await db.Files.FirstOrDefaultAsync(f => f.Id == req.FileId && f.OwnerId == userId);
            if (file == null) return Results.NotFound(new { Message = "File not found or unauthorized." });

            var share = new ShareLink
            {
                FileItemId = file.Id,
                Token = Guid.NewGuid().ToString("N"), // Cryptographically secure UUID
                Expiry = DateTime.UtcNow.AddMinutes(req.ExpiryMinutes > 0 ? req.ExpiryMinutes : 60),
                Permission = req.Permission == "Download" ? "Download" : "View"
            };

            if (!string.IsNullOrEmpty(req.Password))
            {
                share.PasswordHash = PasswordHasher.HashPassword(req.Password);
            }

            db.ShareLinks.Add(share);
            await db.SaveChangesAsync();

            return Results.Ok(new { Message = "Share link created.", Token = share.Token, Expiry = share.Expiry });
        }).RequireAuthorization();

        // GET ACTIVE LINKS FOR A FILE
        group.MapGet("/file/{fileId:int}", async (int fileId, HttpContext context, SecureHubDbContext db) =>
        {
            var userIdStr = context.User.FindFirstValue(ClaimTypes.NameIdentifier);
            if (!int.TryParse(userIdStr, out var userId)) return Results.Unauthorized();

            // IDOR Protection: Owner check
            var file = await db.Files.FirstOrDefaultAsync(f => f.Id == fileId && f.OwnerId == userId);
            if (file == null) return Results.NotFound(new { Message = "File not found or unauthorized." });

            var activeShares = await db.ShareLinks
                .Where(s => s.FileItemId == fileId && s.Expiry > DateTime.UtcNow)
                .Select(s => new ShareLinkDto(s.Id, s.Token, s.Expiry, !string.IsNullOrEmpty(s.PasswordHash), s.Permission))
                .ToListAsync();

            return Results.Ok(activeShares);
        }).RequireAuthorization();

        // REVOKE (DELETE) A LINK
        group.MapDelete("/{id:int}", async (int id, HttpContext context, SecureHubDbContext db) =>
        {
            var userIdStr = context.User.FindFirstValue(ClaimTypes.NameIdentifier);
            if (!int.TryParse(userIdStr, out var userId)) return Results.Unauthorized();

            // Join with FileItem to enforce IDOR
            var share = await db.ShareLinks.Include(s => s.FileItem).FirstOrDefaultAsync(s => s.Id == id);
            if (share == null || share.FileItem!.OwnerId != userId) 
                return Results.NotFound(new { Message = "Share link not found or unauthorized." });

            db.ShareLinks.Remove(share);
            await db.SaveChangesAsync();

            return Results.Ok(new { Message = "Share link revoked successfully." });
        }).RequireAuthorization();

        // ACCESS LINK
        group.MapGet("/{token}", async (string token, [Microsoft.AspNetCore.Mvc.FromQuery] string? pwd, HttpContext context, SecureHubDbContext db, AesEncryptionService encryptionService) =>
        {
            var share = await db.ShareLinks.Include(s => s.FileItem).FirstOrDefaultAsync(s => s.Token == token);
            if (share == null) return Results.NotFound(new { Message = "Invalid share link." });

            if (DateTime.UtcNow > share.Expiry)
                return Results.BadRequest(new { Message = "Share link has expired." });

            if (!string.IsNullOrEmpty(share.PasswordHash))
            {
                bool isPasswordWrong = !string.IsNullOrEmpty(pwd) && !PasswordHasher.VerifyPassword(pwd, share.PasswordHash);
                
                if (string.IsNullOrEmpty(pwd) || isPasswordWrong)
                {
                    // Return a professional UI form for browser users to enter the password manually
                    var errorHtml = isPasswordWrong ? "<div style='color: #ef4444; font-size: 0.85rem; margin-top: 1rem;'>⚠️ Incorrect password. Please try again.</div>" : "";
                    
                    var html = $@"
                        <!DOCTYPE html>
                        <html lang='en'>
                        <head>
                            <meta charset='UTF-8'>
                            <meta name='viewport' content='width=device-width, initial-scale=1.0'>
                            <title>Secure File Share</title>
                            <style>
                                body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f8fafc; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; }}
                                .card {{ background: white; padding: 2.5rem 2rem; border-radius: 12px; box-shadow: 0 10px 15px -3px rgb(0 0 0 / 0.1); text-align: center; max-width: 380px; width: 90%; border: 1px solid #e2e8f0; }}
                                h2 {{ color: #1e293b; margin-top: 0; font-size: 1.5rem; }}
                                p {{ color: #64748b; font-size: 0.95rem; margin-bottom: 1.5rem; line-height: 1.5; }}
                                input {{ box-sizing: border-box; width: 100%; padding: 0.8rem; border: 1px solid #cbd5e1; border-radius: 8px; margin-bottom: 1.2rem; font-size: 1rem; }}
                                input:focus {{ outline: none; border-color: #6366f1; box-shadow: 0 0 0 3px rgba(99,102,241,0.2); }}
                                button {{ background: #6366f1; color: white; border: none; padding: 0.8rem; border-radius: 8px; cursor: pointer; font-weight: bold; width: 100%; font-size: 1rem; transition: background 0.2s; }}
                                button:hover {{ background: #4f46e5; }}
                            </style>
                        </head>
                        <body>
                            <div class='card'>
                                <h2>🔒 Protected File</h2>
                                <p>This SecureHub shared file is protected. Please enter the password to {share.Permission.ToLower()} it.</p>
                                <form method='GET'>
                                    <input type='password' name='pwd' placeholder='Enter your password' required autofocus>
                                    <button type='submit'>Unlock File</button>
                                </form>
                                {errorHtml}
                            </div>
                        </body>
                        </html>";

                    return Results.Content(html, "text/html");
                }
            }

            var physicalPath = Path.Combine(StorageDirectory, share.FileItem!.StorageFileName);
            if (!File.Exists(physicalPath)) return Results.NotFound(new { Message = "Physical file missing." });

            context.Response.ContentType = share.FileItem.MimeType ?? "application/octet-stream";
            
            // Set download vs inline behavior
            var disposition = share.Permission == "Download" ? "attachment" : "inline";
            var cd = new System.Net.Mime.ContentDisposition
            {
                FileName = share.FileItem.FileName,
                Inline = share.Permission != "Download"
            };
            context.Response.Headers.Append("Content-Disposition", cd.ToString());

            using var sourceStream = new FileStream(physicalPath, FileMode.Open, FileAccess.Read);
            await encryptionService.DecryptStreamAsync(sourceStream, context.Response.Body);

            return Results.Empty;
        });
    }
}

public record CreateShareRequest(int FileId, int ExpiryMinutes, string? Password, string Permission);
public record ShareLinkDto(int Id, string Token, DateTime Expiry, bool HasPassword, string Permission);
