using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using System.Threading.Tasks;

namespace SecureHub.Client.Services;

public class ApiClient
{
    private readonly HttpClient _http;
    public string BaseUrl { get; }

    public static ApiClient Instance { get; private set; } = null!;

    public static void Initialize(string baseUrl)
    {
        Instance = new ApiClient(baseUrl);
    }

    private ApiClient(string baseUrl)
    {
        BaseUrl = baseUrl;
        if (OperatingSystem.IsBrowser())
        {
            // WASM inherently trusts the browser's certificate chain and doesn't support HttpClientHandler bypass
            _http = new HttpClient { BaseAddress = new Uri(baseUrl) };
        }
        else
        {
            // Desktop and Mobile: Enable CookieContainer for HttpOnly JWT cookie transport
            // + Bypass self-signed development certificate blocks
            var cookieContainer = new CookieContainer();
            var handler = new HttpClientHandler
            {
                CookieContainer = cookieContainer,
                UseCookies = true,
                ServerCertificateCustomValidationCallback = (message, cert, chain, errors) => true
            };
            _http = new HttpClient(handler) { BaseAddress = new Uri(baseUrl) };
        }
    }

    // ==================== AUTH ====================

    public async Task<(bool success, string message)> LoginAsync(string email, string password)
    {
        var response = await _http.PostAsJsonAsync("/api/auth/login", new { Email = email, Password = password });
        if (response.IsSuccessStatusCode)
        {
            if (OperatingSystem.IsBrowser())
            {
                try
                {
                    var content = await response.Content.ReadAsStringAsync();
                    using var doc = JsonDocument.Parse(content);
                    if (doc.RootElement.TryGetProperty("token", out var tProp) || doc.RootElement.TryGetProperty("Token", out tProp))
                    {
                        var tokenVal = tProp.GetString();
                        if (!string.IsNullOrEmpty(tokenVal))
                        {
                            _http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", tokenVal);
                        }
                    }
                }
                catch { }
            }
            return (true, "Login Success");
        }

        if (response.StatusCode == HttpStatusCode.TooManyRequests)
            return (false, "Too many attempts. Please wait 1 minute.");

        return (false, "Access Denied: Invalid credentials.");
    }

    public async Task<(bool success, string message)> RegisterAsync(string email, string password)
    {
        var response = await _http.PostAsJsonAsync("/api/auth/register", new { Email = email, Password = password });
        if (response.IsSuccessStatusCode) return (true, "Account created successfully.");

        return (false, "Registration Failed: Requirements not met (e.g. weak password or duplicate email).");
    }

    public async Task LogoutAsync()
    {
        await _http.PostAsync("/api/auth/logout", null);
        if (OperatingSystem.IsBrowser())
        {
            _http.DefaultRequestHeaders.Authorization = null;
        }
    }

    // ==================== FILES ====================

    public async Task<List<FileItemDto>> GetMyFilesAsync()
    {
        var response = await _http.GetAsync("/api/files");
        if (response.IsSuccessStatusCode && response.Content != null)
        {
            var content = await response.Content.ReadAsStringAsync();
            if (!string.IsNullOrWhiteSpace(content))
            {
                return JsonSerializer.Deserialize<List<FileItemDto>>(content, new JsonSerializerOptions { PropertyNameCaseInsensitive = true }) ?? new List<FileItemDto>();
            }
        }
        return new List<FileItemDto>();
    }

    public async Task<(bool success, string message)> UploadFileAsync(string filePath, string? description)
    {
        using var fileStream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read);
        using var form = new MultipartFormDataContent();
        var fileContent = new StreamContent(fileStream);
        fileContent.Headers.ContentType = new MediaTypeHeaderValue(GuessMimeType(filePath));
        form.Add(fileContent, "file", Path.GetFileName(filePath));

        if (!string.IsNullOrWhiteSpace(description))
        {
            form.Add(new StringContent(description), "description");
        }

        var response = await _http.PostAsync("/api/files/upload", form);
        if (response.IsSuccessStatusCode) return (true, "File uploaded and encrypted.");

        var body = await response.Content.ReadAsStringAsync();
        return (false, $"Upload failed: {body}");
    }

    public async Task<(bool success, string message)> UploadFileAsync(Stream fileStream, string fileName, string? description)
    {
        using var form = new MultipartFormDataContent();
        var fileContent = new StreamContent(fileStream);
        fileContent.Headers.ContentType = new MediaTypeHeaderValue(GuessMimeType(fileName));
        form.Add(fileContent, "file", fileName);

        if (!string.IsNullOrWhiteSpace(description))
        {
            form.Add(new StringContent(description), "description");
        }

        var response = await _http.PostAsync("/api/files/upload", form);
        if (response.IsSuccessStatusCode) return (true, "File uploaded and encrypted.");

        var body = await response.Content.ReadAsStringAsync();
        return (false, $"Upload failed: {body}");
    }

    public async Task<(bool success, Stream? dataStream, string fileName)> DownloadFileAsync(int fileId)
    {
        var response = await _http.GetAsync($"/api/files/{fileId}/download", HttpCompletionOption.ResponseHeadersRead);
        if (!response.IsSuccessStatusCode) return (false, null, "");

        var dataStream = await response.Content.ReadAsStreamAsync();
        var fileName = response.Content.Headers.ContentDisposition?.FileName?.Trim('"') ?? "download";
        return (true, dataStream, fileName);
    }

    public async Task<(bool success, string message)> DeleteFileAsync(int fileId)
    {
        var response = await _http.DeleteAsync($"/api/files/{fileId}");
        return (response.IsSuccessStatusCode, response.IsSuccessStatusCode ? "File deleted." : "Delete failed.");
    }

    // ==================== SHARES ====================

    public async Task<(bool success, string token, string message)> CreateShareLinkAsync(int fileId, int expiryMinutes, string? password, string permission)
    {
        var response = await _http.PostAsJsonAsync("/api/shares", new
        {
            FileId = fileId,
            ExpiryMinutes = expiryMinutes,
            Password = password,
            Permission = permission
        });

        if (response.IsSuccessStatusCode)
        {
            var content = await response.Content.ReadAsStringAsync();
            using var doc = JsonDocument.Parse(content);
            var token = doc.RootElement.TryGetProperty("token", out var t1) ? t1.GetString() 
                      : (doc.RootElement.TryGetProperty("Token", out var t2) ? t2.GetString() : "");
            
            return (true, token ?? "", "Share link created.");
        }
        return (false, "", "Failed to create share link.");
    }

    public async Task<List<ShareLinkDto>> GetActiveSharesAsync(int fileId)
    {
        var response = await _http.GetAsync($"/api/shares/file/{fileId}");
        if (response.IsSuccessStatusCode && response.Content != null)
        {
            var content = await response.Content.ReadAsStringAsync();
            if (!string.IsNullOrWhiteSpace(content))
            {
                return JsonSerializer.Deserialize<List<ShareLinkDto>>(content, new JsonSerializerOptions { PropertyNameCaseInsensitive = true }) ?? new List<ShareLinkDto>();
            }
        }
        return new List<ShareLinkDto>();
    }

    public async Task<(bool success, string message)> RevokeShareLinkAsync(int shareId)
    {
        var response = await _http.DeleteAsync($"/api/shares/{shareId}");
        return (response.IsSuccessStatusCode, response.IsSuccessStatusCode ? "Share revoked." : "Fail to revoke.");
    }

    // ==================== USER ====================

    public async Task<(bool success, string message)> EraseAccountAsync(string password)
    {
        var request = new HttpRequestMessage(HttpMethod.Delete, "/api/users/me");
        request.Content = JsonContent.Create(new { Password = password });

        var response = await _http.SendAsync(request);
        return (response.IsSuccessStatusCode, response.IsSuccessStatusCode ? "Account Erased." : "Failed to erase account.");
    }

    // ==================== HELPERS ====================

    private static string GuessMimeType(string path)
    {
        var ext = Path.GetExtension(path).ToLowerInvariant();
        return ext switch
        {
            ".pdf" => "application/pdf",
            ".docx" => "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            ".png" => "image/png",
            ".jpg" or ".jpeg" => "image/jpeg",
            ".txt" => "text/plain",
            _ => "application/octet-stream"
        };
    }
}

public class FileItemDto
{
    public int Id { get; set; }
    public string FileName { get; set; } = "";
    public string? Description { get; set; }
    public string? MimeType { get; set; }
    public long SizeBytes { get; set; }
    public DateTime UploadedAt { get; set; }
}

public class ShareLinkDto
{
    public int Id { get; set; }
    public string Token { get; set; } = "";
    public DateTime Expiry { get; set; }
    public bool HasPassword { get; set; }
    public string Permission { get; set; } = "View";
}
