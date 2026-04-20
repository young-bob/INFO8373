using System;
using System.Collections.Generic;

namespace SecureHub.Api.Models;

public class User
{
    public int Id { get; init; }
    public required string Email { get; set; }
    public required string PasswordHash { get; set; }
    public string Role { get; set; } = "User"; // User or Admin
    public DateTime CreatedAt { get; init; } = DateTime.UtcNow;
    
    public ICollection<FileItem> Files { get; set; } = new List<FileItem>();
}

public class FileItem
{
    public int Id { get; init; }
    public int OwnerId { get; init; } // Unencrypted FK to prevent IDOR natively
    public User? Owner { get; set; }
    
    // Encrypted Metadata
    public required string FileName { get; set; } 
    public string? Description { get; set; }
    public string? MimeType { get; set; }
    
    // Internal Storage mapping
    public required string StorageFileName { get; set; } // UUID, prevents path traversal
    public long SizeBytes { get; set; }
    public DateTime UploadedAt { get; init; } = DateTime.UtcNow;
}

public class ShareLink
{
    public int Id { get; init; }
    public int FileItemId { get; init; } // The target file
    public FileItem? FileItem { get; set; }
    
    public required string Token { get; init; } // Secure UUID token
    public DateTime Expiry { get; init; }
    public string? PasswordHash { get; set; } // Optional password
    public string Permission { get; set; } = "View"; // 'View' or 'Download'
}

public class AuditLog
{
    public int Id { get; init; }
    public int? UserId { get; init; } // Nullable, as unauthenticated users leave logs too (e.g. invalid login)
    public required string Action { get; init; }
    public required string IpAddress { get; init; }
    public DateTime Timestamp { get; init; } = DateTime.UtcNow;
}
