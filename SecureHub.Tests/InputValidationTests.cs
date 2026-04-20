using FluentAssertions;
using SecureHub.Api.Endpoints;
using Xunit;

namespace SecureHub.Tests;

public class InputValidationTests
{
    private readonly RegisterRequestValidator _validator = new();

    [Theory]
    [InlineData("weakpass", false)] // No uppercase, no numbers, no special chars, too short
    [InlineData("NoSpecialChar123", false)] // Valid length, upper, lower, numbers - but missing special char
    [InlineData("nouppercase123!", false)] // Missing uppercase
    [InlineData("NOLOWERCASE123!", false)] // Missing lowercase
    [InlineData("NoNumbersHere!!", false)] // Missing numeric
    [InlineData("Valid123!Secure", true)] // Meets all complexity rules
    public void RegisterRequest_PasswordStrength_ShouldBeStrictlyEnforced(string password, bool expectedValid)
    {
        // Arrange
        var request = new RegisterRequest("test@securehub.local", password);

        // Act
        var result = _validator.Validate(request);

        // Assert
        result.IsValid.Should().Be(expectedValid);
    }
    
    [Theory]
    [InlineData("plainaddress", false)]
    [InlineData("@missingusername.com", false)]
    [InlineData("admin@securehub.local", true)]
    public void RegisterRequest_EmailFormat_ShouldBeStrictlyEnforced(string email, bool expectedValid)
    {
        // Arrange
        var request = new RegisterRequest(email, "Valid123!Secure");

        // Act
        var result = _validator.Validate(request);

        // Assert
        result.IsValid.Should().Be(expectedValid);
    }
}
