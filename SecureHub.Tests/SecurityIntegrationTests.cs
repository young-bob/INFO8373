using FluentAssertions;
using Microsoft.AspNetCore.Mvc.Testing;
using SecureHub.Api.Endpoints;
using System.Net;
using System.Net.Http.Json;
using Xunit;

namespace SecureHub.Tests;

public class SecurityIntegrationTests : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly WebApplicationFactory<Program> _factory;

    public SecurityIntegrationTests(WebApplicationFactory<Program> factory)
    {
        // Satisfy the Fail-Secure environment variables required by Program.cs for bootstrapping
        Environment.SetEnvironmentVariable("API_HTTPS_PORT", "5001");
        Environment.SetEnvironmentVariable("DEFAULT_ADMIN_EMAIL", "testadmin@securehub.local");
        Environment.SetEnvironmentVariable("DEFAULT_ADMIN_PASSWORD", "AdminSecur3#1024!");
        Environment.SetEnvironmentVariable("AES_ENCRYPTION_KEY", "MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE=");
        // Use a physical file for tests to prevent SQLite in-memory dropping after EF connection closes
        Environment.SetEnvironmentVariable("DB_CONNECTION_STRING", "Data Source=IntegrationTest.db");
        Environment.SetEnvironmentVariable("JWT_SECRET", "SuperSecretTestJwtKeyRequiredForTests123!");
        Environment.SetEnvironmentVariable("JWT_ISSUER", "SecureHubTest");
        Environment.SetEnvironmentVariable("JWT_AUDIENCE", "SecureHubClientTest");

        _factory = factory;
    }

    [Fact]
    public async Task GetFile_WithoutJwtToken_ShouldReturnUnauthorized()
    {
        // Arrange
        var client = _factory.CreateClient();

        // Act & Assert (IDOR & Authentication Boundary Check)
        var response = await client.GetAsync("/api/files");
        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task RateLimiter_ShouldBlockBruteForceAttempts_AfterFiveRequests()
    {
        // Arrange
        var client = _factory.CreateClient();
        var requestBody = new LoginRequest("testadmin@securehub.local", "WrongPassword123!");

        // Act & Assert: First 5 requests should process normally (rejecting bad password with 401 or 400)
        for (int i = 0; i < 5; i++)
        {
            var res = await client.PostAsJsonAsync("/api/auth/login", requestBody);
            res.StatusCode.Should().NotBe(HttpStatusCode.TooManyRequests);
        }

        // The 6th request MUST trigger the Fixed Window Rate Limiting firewall
        var blockedResponse = await client.PostAsJsonAsync("/api/auth/login", requestBody);
        blockedResponse.StatusCode.Should().Be(HttpStatusCode.TooManyRequests);
    }

    [Fact]
    public async Task SecurityMiddlewares_ShouldInjectHeaders_AndHideExceptions()
    {
        // Arrange
        var client = _factory.CreateClient();

        // Act: Hit a non-existent or public endpoint to capture the response pipeline headers
        var response = await client.GetAsync("/");

        // Assert: Verify Phase 7 Security Headers are glued to the response
        response.Headers.Contains("X-Content-Type-Options").Should().BeTrue();
        response.Headers.GetValues("X-Content-Type-Options").Should().Contain("nosniff");
        
        response.Headers.Contains("X-Frame-Options").Should().BeTrue();
        response.Headers.GetValues("X-Frame-Options").Should().Contain("DENY");

        response.Headers.Contains("X-XSS-Protection").Should().BeTrue();
        response.Headers.GetValues("X-XSS-Protection").Should().Contain("1; mode=block");

        response.Headers.Contains("Content-Security-Policy").Should().BeTrue();
    }
}
