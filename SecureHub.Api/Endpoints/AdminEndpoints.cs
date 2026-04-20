using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using SecureHub.Api.Data;
using System.Security.Claims;

namespace SecureHub.Api.Endpoints;

public static class AdminEndpoints
{
    public static void MapAdminEndpoints(this IEndpointRouteBuilder app)
    {
        var group = app.MapGroup("/api/admin").WithTags("Administration").RequireAuthorization();

        // Phase 6.1: Admin Audit Log Viewer
        // Only users with 'Admin' role can access the full audit trail.
        group.MapGet("/audit-logs", async (
            HttpContext context,
            [FromServices] SecureHubDbContext db,
            [FromQuery] int page = 1,
            [FromQuery] int pageSize = 50) =>
        {
            // Server-side RBAC enforcement — not just UI hiding
            var role = context.User.FindFirstValue(ClaimTypes.Role);
            if (role != "Admin")
            {
                return Results.Forbid();
            }

            var totalCount = await db.AuditLogs.CountAsync();

            var logs = await db.AuditLogs
                .OrderByDescending(l => l.Timestamp)
                .Skip((page - 1) * pageSize)
                .Take(pageSize)
                .Select(l => new
                {
                    l.Id,
                    l.UserId,
                    l.Action,
                    l.IpAddress,
                    l.Timestamp
                })
                .ToListAsync();

            return Results.Ok(new
            {
                TotalCount = totalCount,
                Page = page,
                PageSize = pageSize,
                Data = logs
            });
        });
    }
}
