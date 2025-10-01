using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;

namespace VehicleRegistryAPI.Middleware
{
    public class RateLimitingMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly ILogger<RateLimitingMiddleware> _logger;
        private static readonly Dictionary<string, List<DateTime>> _requests = new();

        public RateLimitingMiddleware(RequestDelegate next, ILogger<RateLimitingMiddleware> logger)
        {
            _next = next;
            _logger = logger;
        }

        public async Task InvokeAsync(HttpContext context)
        {
            var ip = context.Connection.RemoteIpAddress?.ToString() ?? "unknown";
            var path = context.Request.Path;

            // Aplicar rate limiting apenas para login
            if (path.StartsWithSegments("/api/auth/login"))
            {
                if (!_requests.ContainsKey(ip))
                    _requests[ip] = new List<DateTime>();

                // Remover requisições antigas (últimos 15 minutos)
                _requests[ip].RemoveAll(t => t < DateTime.UtcNow.AddMinutes(-15));

                // Limitar para 5 tentativas por 15 minutos
                if (_requests[ip].Count >= 5)
                {
                    _logger.LogWarning("Rate limit excedido para IP: {IP}", ip);
                    context.Response.StatusCode = StatusCodes.Status429TooManyRequests;
                    await context.Response.WriteAsync("Muitas tentativas. Tente novamente em 15 minutos.");
                    return;
                }

                _requests[ip].Add(DateTime.UtcNow);
            }

            await _next(context);
        }
    }
}