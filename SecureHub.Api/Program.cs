using System.Text;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.RateLimiting;
using DotNetEnv;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using SecureHub.Api.Data;
using SecureHub.Api.Middleware;
using SecureHub.Api.Security;
using SecureHub.Api.Endpoints;

// In a Docker environment, variables are natively injected into the OS via 'docker run -e' or 'docker-compose'.
// The .env file is strictly for local physical development. We gracefully load it only if it's explicitly present.
if (System.IO.File.Exists(".env"))
{
    DotNetEnv.Env.Load();
}

var builder = WebApplication.CreateBuilder(args);

// Port binding: In Docker, ASPNETCORE_URLS is injected by compose (HTTP behind Nginx TLS termination).
// Locally, we enforce HTTPS-only to prevent SSL Stripping attacks.
var aspnetUrls = Environment.GetEnvironmentVariable("ASPNETCORE_URLS");
if (string.IsNullOrEmpty(aspnetUrls))
{
    var httpsPort = Environment.GetEnvironmentVariable("API_HTTPS_PORT") 
                    ?? throw new InvalidOperationException("CRITICAL: API_HTTPS_PORT is strictly required.");
    builder.WebHost.UseUrls($"https://*:{httpsPort}");
}

// Configure Kestrel to accept file uploads up to 15MB (our app limit is 10MB + overhead)
builder.WebHost.ConfigureKestrel(options =>
{
    options.Limits.MaxRequestBodySize = 15 * 1024 * 1024;
});

// Configure form options for multipart file uploads
builder.Services.Configure<Microsoft.AspNetCore.Http.Features.FormOptions>(options =>
{
    options.MultipartBodyLengthLimit = 15 * 1024 * 1024;
});

// 1. Initialize AES Encryption Service
var encryptionKey = Environment.GetEnvironmentVariable("AES_ENCRYPTION_KEY") 
                    ?? throw new InvalidOperationException("CRITICAL: AES_ENCRYPTION_KEY environment variable is missing.");
builder.Services.AddSingleton(new AesEncryptionService(encryptionKey));

// 2. Configure Entity Framework SQLite
var connectionString = Environment.GetEnvironmentVariable("DB_CONNECTION_STRING") 
                       ?? throw new InvalidOperationException("CRITICAL: DB_CONNECTION_STRING is strictly required.");
builder.Services.AddDbContext<SecureHubDbContext>(options => options.UseSqlite(connectionString));

// 3. Configure JWT Authentication
var jwtSecret = Environment.GetEnvironmentVariable("JWT_SECRET") 
                ?? throw new InvalidOperationException("CRITICAL: JWT_SECRET environment variable is missing.");
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = Environment.GetEnvironmentVariable("JWT_ISSUER"),
            ValidAudience = Environment.GetEnvironmentVariable("JWT_AUDIENCE"),
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSecret))
        };
        // Fix for Cookie reading of JWT
        options.Events = new JwtBearerEvents
        {
            OnMessageReceived = context =>
            {
                if (context.Request.Cookies.TryGetValue("SecureHubToken", out var token))
                {
                    context.Token = token;
                }
                return Task.CompletedTask;
            }
        };
    });
builder.Services.AddAuthorization();

// 4. Configure Brute-Force Rate Limiting (Phase 2 Task 2.3)
builder.Services.AddRateLimiter(options =>
{
    // Restrict global login endpoint to combat brute-forcing
    options.AddFixedWindowLimiter("LoginLimiter", opt => {
        opt.PermitLimit = 5; // 5 attempts
        opt.Window = TimeSpan.FromMinutes(1); // Per minute
        opt.QueueProcessingOrder = QueueProcessingOrder.OldestFirst;
        opt.QueueLimit = 0; // Reject immediately if over quota
    });
    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
});

// 5. Configure CORS for WebAssembly Client
builder.Services.AddCors(options =>
{
    options.AddPolicy("WasmCorsApp", policy =>
    {
        policy.WithOrigins(
                "https://localhost:7169",  // Avalonia Browser dev server
                "http://localhost:5235",   // Avalonia Browser alt dev server
                "https://localhost"        // Docker Compose (Nginx TLS)
              )
              .AllowAnyMethod()
              .AllowAnyHeader()
              .AllowCredentials();
    });
});

var app = builder.Build();

// Seed Database automatically on startup
using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<SecureHubDbContext>();
    db.Database.Migrate(); // Ensure DB is fully created and migrated
    
    var adminEmail = Environment.GetEnvironmentVariable("DEFAULT_ADMIN_EMAIL") 
                     ?? throw new InvalidOperationException("CRITICAL: DEFAULT_ADMIN_EMAIL is strictly required.");
    var adminPassword = Environment.GetEnvironmentVariable("DEFAULT_ADMIN_PASSWORD");

    if (!string.IsNullOrEmpty(adminPassword) && !db.Users.Any(u => u.Role == "Admin"))
    {
        db.Users.Add(new SecureHub.Api.Models.User
        {
            Email = adminEmail,
            PasswordHash = PasswordHasher.HashPassword(adminPassword),
            Role = "Admin",
            CreatedAt = DateTime.UtcNow
        });
        db.SaveChanges();
    }
}

// Add custom Phase 7 security middlewares
app.UseMiddleware<GlobalExceptionHandlerMiddleware>();
app.UseMiddleware<SecurityHeadersMiddleware>();

if (!app.Environment.IsDevelopment())
{
    // Enforce Strict-Transport-Security (HSTS) in Production for TLS
    app.UseHsts();
}

// In Docker, Nginx handles TLS termination; skip HTTPS redirect to avoid infinite loops
if (string.IsNullOrEmpty(Environment.GetEnvironmentVariable("ASPNETCORE_FORWARDEDHEADERS_ENABLED")))
{
    app.UseHttpsRedirection(); // Enforce HTTPS routing (local dev only)
}
app.UseCors("WasmCorsApp"); // Enable CORS before Auth
app.UseRateLimiter();
app.UseAuthentication();
app.UseAuthorization();

// Security Phase 6: Privacy, Audit Logging
app.UseMiddleware<AuditLogMiddleware>();

app.MapGet("/", () => "SecureHub Vault API is online and secured.");

// API Endpoints
app.MapAuthEndpoints();
app.MapFileEndpoints();
app.MapShareEndpoints();
app.MapUserEndpoints();
app.MapAdminEndpoints();

app.Run();

// Required to expose the minimal API Program class to the WebApplicationFactory in the Test Project
public partial class Program { }
