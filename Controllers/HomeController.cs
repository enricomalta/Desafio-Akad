using System;
using System.Linq;
using System.Threading.Tasks;
using System.Collections.Generic;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using VehicleRegistryAPI.Data;
using VehicleRegistryAPI.DTOs;
using VehicleRegistryAPI.Models;
using VehicleRegistryAPI.Services;
using VehicleRegistryAPI.Repository;

namespace VehicleRegistryAPI.Controllers
{
    [ApiController]
    [Route("/")]
    public class HomeController : ControllerBase
    {
        [HttpGet]
        public IActionResult Get()
        {
            var response = new
            {
                System = "Vehicle Registry API",
                Status = "Online",
                Version = "1.0.0",
                Environment = Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT") ?? "Production",
                Timestamp = DateTime.UtcNow
            };

            return Ok(response);
        }
    }

    [ApiController]
    [Route("api/[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly ApplicationDbContext _context;
        private readonly IPasswordHasher _passwordHasher;
        private readonly IJwtService _jwtService;

        public AuthController(ApplicationDbContext context, IPasswordHasher passwordHasher, IJwtService jwtService)
        {
            _context = context;
            _passwordHasher = passwordHasher;
            _jwtService = jwtService;
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginDto loginDto)
        {
            var username = loginDto.Username.Trim().ToLower();
            var password = loginDto.Password.Trim();

            var user = await _context.Users
                .Include(u => u.RefreshTokens)
                .FirstOrDefaultAsync(u => u.Username == username);

            if (user == null || !_passwordHasher.VerifyPassword(password, user.PasswordHash))
            {
                await Task.Delay(Random.Shared.Next(200, 500));
                return Unauthorized(new { message = "Credenciais inválidas" });
            }

            user.LastLogin = DateTime.UtcNow;
            await _context.SaveChangesAsync();

            var token = _jwtService.GenerateToken(user);
            var refreshToken = _jwtService.GenerateRefreshToken();

            user.RefreshTokens.Add(new RefreshToken
            {
                Token = refreshToken,
                Expires = DateTime.UtcNow.AddDays(7),
                Created = DateTime.UtcNow,
                CreatedByIp = GetIpAddress()
            });

            await _context.SaveChangesAsync();

            var response = new AuthResponseDto
            {
                Token = token,
                RefreshToken = refreshToken,
                Expires = DateTime.UtcNow.AddMinutes(15),
                Username = user.Username,
                Role = user.Role,
                ForcePasswordReset = user.ForcePasswordReset
            };

            return Ok(response);
        }

        [HttpPost("refresh")]
        public async Task<IActionResult> Refresh([FromBody] string refreshToken)
        {
            var now = DateTime.UtcNow; ; // add
            var user = await _context.Users
                .Include(u => u.RefreshTokens)
                // .FirstOrDefaultAsync(u => u.RefreshTokens.Any(rt => rt.Token == refreshToken && rt.IsActive));
                .FirstOrDefaultAsync(u => u.RefreshTokens.Any(rt => rt.Token == refreshToken && rt.Revoked == null && rt.Expires > now));

            if (user == null)
                return Unauthorized(new { message = "Token inválido" });

            var newToken = _jwtService.GenerateToken(user);
            var newRefreshToken = _jwtService.GenerateRefreshToken();

            var oldToken = user.RefreshTokens.First(rt => rt.Token == refreshToken);
            oldToken.Revoked = DateTime.UtcNow;
            oldToken.RevokedByIp = GetIpAddress();
            oldToken.ReplacedByToken = newRefreshToken;

            user.RefreshTokens.Add(new RefreshToken
            {
                Token = newRefreshToken,
                Expires = DateTime.UtcNow.AddDays(7),
                Created = DateTime.UtcNow,
                CreatedByIp = GetIpAddress()
            });

            await _context.SaveChangesAsync();

            var response = new AuthResponseDto
            {
                Token = newToken,
                RefreshToken = newRefreshToken,
                Expires = DateTime.UtcNow.AddMinutes(15),
                Username = user.Username,
                Role = user.Role,
                ForcePasswordReset = user.ForcePasswordReset
            };

            return Ok(response);
        }

        private string GetIpAddress()
        {
            return HttpContext.Connection.RemoteIpAddress?.ToString() ?? "Unknown";
        }
    }

    [ApiController]
    [Route("api/[controller]")]
    [Authorize]
    public class VehiclesController : ControllerBase
    {
        private readonly IVehicleRepository _vehicleRepository;
        private readonly ILogger<VehiclesController> _logger;

        public VehiclesController(IVehicleRepository vehicleRepository, ILogger<VehiclesController> logger)
        {
            _vehicleRepository = vehicleRepository;
            _logger = logger;
        }

        [HttpGet]
        public async Task<ActionResult<IEnumerable<Vehicle>>> GetVehicles()
        {
            var vehicles = await _vehicleRepository.GetAllAsync();
            return Ok(vehicles);
        }

        [HttpGet("{id}")]
        public async Task<ActionResult<Vehicle>> GetVehicle(int id)
        {
            var vehicle = await _vehicleRepository.GetByIdAsync(id);
            
            if (vehicle == null)
                return NotFound(new { message = "Veículo não encontrado" });

            return Ok(vehicle);
        }

        [HttpPost]
        [Authorize(Roles = "Admin,Editor")]
        public async Task<ActionResult<Vehicle>> CreateVehicle(VehicleDto vehicleDto)
        {
            var licensePlate = vehicleDto.LicensePlate.Trim().ToUpper();
            
            if (await _vehicleRepository.ExistsAsync(licensePlate))
                return Conflict(new { message = "Já existe um veículo com esta placa" });

            var vehicle = new Vehicle
            {
                LicensePlate = licensePlate,
                Brand = vehicleDto.Brand.Trim(),
                Model = vehicleDto.Model.Trim(),
                Year = vehicleDto.Year,
                Color = vehicleDto.Color.Trim(),
                CreatedBy = User.Identity?.Name ?? "Unknown"
            };

            var createdVehicle = await _vehicleRepository.CreateAsync(vehicle);
            
            _logger.LogInformation("Veículo {LicensePlate} criado por {User}", 
                createdVehicle.LicensePlate, User.Identity?.Name);

            return CreatedAtAction(nameof(GetVehicle), new { id = createdVehicle.Id }, createdVehicle);
        }

        [HttpPut("{id}")]
        [Authorize(Roles = "Admin,Editor")]
        public async Task<IActionResult> UpdateVehicle(int id, VehicleDto vehicleDto)
        {
            var existingVehicle = await _vehicleRepository.GetByIdAsync(id);
            if (existingVehicle == null)
                return NotFound(new { message = "Veículo não encontrado" });

            var licensePlate = vehicleDto.LicensePlate.Trim().ToUpper();
            if (licensePlate != existingVehicle.LicensePlate && 
                await _vehicleRepository.ExistsAsync(licensePlate))
                return Conflict(new { message = "Já existe um veículo com esta placa" });

            existingVehicle.LicensePlate = licensePlate;
            existingVehicle.Brand = vehicleDto.Brand.Trim();
            existingVehicle.Model = vehicleDto.Model.Trim();
            existingVehicle.Year = vehicleDto.Year;
            existingVehicle.Color = vehicleDto.Color.Trim();

            await _vehicleRepository.UpdateAsync(existingVehicle);
            
            _logger.LogInformation("Veículo {LicensePlate} atualizado por {User}", 
                existingVehicle.LicensePlate, User.Identity?.Name);

            return NoContent();
        }

        [HttpDelete("{id}")]
        [Authorize(Roles = "Admin")]
        public async Task<IActionResult> DeleteVehicle(int id)
        {
            var vehicle = await _vehicleRepository.GetByIdAsync(id);
            if (vehicle == null)
                return NotFound(new { message = "Veículo não encontrado" });

            await _vehicleRepository.DeleteAsync(id);
            
            _logger.LogInformation("Veículo {LicensePlate} excluído por {User}", 
                vehicle.LicensePlate, User.Identity?.Name);

            return NoContent();
        }
    }
}