using System.Security.Claims;
using Microsoft.EntityFrameworkCore;
using SecureHub.Api.Data;
using SecureHub.Api.Models;
using SecureHub.Api.Security;

namespace SecureHub.Api.Endpoints;

public static class FileEndpoints
{
    private static readonly string StorageDirectory = Path.Combine(Directory.GetCurrentDirectory(), "VaultStorage");
    private static readonly string[] AllowedExtensions = { ".pdf", ".docx", ".png", ".jpg", ".txt" };
    private static readonly string[] AllowedMimeTypes = { "application/pdf", "application/vnd.openxmlformats-officedocument.wordprocessingml.document", "image/png", "image/jpeg", "text/plain" };
    
    private const long MaxFileSize = 10 * 1024 * 1024; // 10 MB

    public static void MapFileEndpoints(this IEndpointRouteBuilder app)
    {
        var group = app.MapGroup("/api/files").WithTags("File Management").RequireAuthorization();

        if (!Directory.Exists(StorageDirectory))
        {
            Directory.CreateDirectory(StorageDirectory);
        }

        group.MapPost("/upload", async (IFormFile file, [Microsoft.AspNetCore.Mvc.FromForm] string? description, HttpContext context, SecureHubDbContext db, AesEncryptionService encryptionService) =>
        {
            var userIdStr = context.User.FindFirstValue(ClaimTypes.NameIdentifier);
            if (!int.TryParse(userIdStr, out var userId)) return Results.Unauthorized();

            // Phase 3: Validation
            if (file == null || file.Length == 0) return Results.BadRequest(new { Message = "File is empty." });
            if (file.Length > MaxFileSize) return Results.BadRequest(new { Message = "File exceeds 10MB limit." });

            var ext = Path.GetExtension(file.FileName).ToLowerInvariant();
            if (!AllowedExtensions.Contains(ext) || !AllowedMimeTypes.Contains(file.ContentType))
            {
                return Results.BadRequest(new { Message = "Invalid file type." });
            }

            // Path Traversal & Isolation Mitigation: Rename to GUID and store outside web root
            var physicalFileName = $"{Guid.NewGuid()}.dat";
            var physicalPath = Path.Combine(StorageDirectory, physicalFileName);

            // Encryption Data at Rest (AES-256 for File stream)
            using (var sourceStream = file.OpenReadStream())
            using (var destinationStream = new FileStream(physicalPath, FileMode.Create))
            {
                await encryptionService.EncryptStreamAsync(sourceStream, destinationStream);
            }

            var fileItem = new FileItem
            {
                OwnerId = userId,
                FileName = file.FileName,             // Will be automatically encrypted by EF Value Converter
                Description = description,            // Will be automatically encrypted by EF Value Converter
                MimeType = file.ContentType,          // Will be automatically encrypted by EF Value Converter
                StorageFileName = physicalFileName,
                SizeBytes = file.Length
            };

            db.Files.Add(fileItem);
            await db.SaveChangesAsync();

            return Results.Ok(new { Message = "File uploaded securely.", FileId = fileItem.Id });
        }).DisableAntiforgery(); // Minimal API IFormFile requires Antiforgery disable if we just use JWT
        
        group.MapGet("/{id:int}/download", async (int id, HttpContext context, SecureHubDbContext db, AesEncryptionService encryptionService) =>
        {
            var userId = int.Parse(context.User.FindFirstValue(ClaimTypes.NameIdentifier)!);

            // IDOR Protection: Must match OwnerId
            var fileItem = await db.Files.FirstOrDefaultAsync(f => f.Id == id && f.OwnerId == userId);
            if (fileItem == null) return Results.NotFound(new { Message = "File not found or unauthorized access." });

            var physicalPath = Path.Combine(StorageDirectory, fileItem.StorageFileName);
            if (!File.Exists(physicalPath)) return Results.NotFound(new { Message = "Physical file missing." });
            
            // Decrypt stream directly to response
            context.Response.ContentType = fileItem.MimeType ?? "application/octet-stream";
            var cd = new System.Net.Mime.ContentDisposition
            {
                FileName = fileItem.FileName,
                Inline = false
            };
            context.Response.Headers.Append("Content-Disposition", cd.ToString());

            using var sourceStream = new FileStream(physicalPath, FileMode.Open, FileAccess.Read);
            await encryptionService.DecryptStreamAsync(sourceStream, context.Response.Body);
            
            return Results.Empty; 
        });

        group.MapDelete("/{id:int}", async (int id, HttpContext context, SecureHubDbContext db) =>
        {
            var userId = int.Parse(context.User.FindFirstValue(ClaimTypes.NameIdentifier)!);

            // IDOR Protection
            var fileItem = await db.Files.FirstOrDefaultAsync(f => f.Id == id && f.OwnerId == userId);
            if (fileItem == null) return Results.NotFound(new { Message = "File not found or unauthorized access." });

            var physicalPath = Path.Combine(StorageDirectory, fileItem.StorageFileName);
            if (File.Exists(physicalPath))
            {
                File.Delete(physicalPath); // Secure physical delete
            }

            db.Files.Remove(fileItem); // Secure logical delete (Cascades shares)
            await db.SaveChangesAsync();

            return Results.Ok(new { Message = "File deleted successfully." });
        });
        
        group.MapGet("/", async (HttpContext context, SecureHubDbContext db) =>
        {
            var userId = int.Parse(context.User.FindFirstValue(ClaimTypes.NameIdentifier)!);
            var files = await db.Files.Where(f => f.OwnerId == userId).ToListAsync();
            
            // Note: Data is decrypted into memory by EF Value Converter automatically!
            var result = files.Select(f => new {
                f.Id, f.FileName, f.Description, f.MimeType, f.SizeBytes, f.UploadedAt
            });
            
            return Results.Ok(result);
        });
    }
}
