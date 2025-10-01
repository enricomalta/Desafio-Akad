// DTOs/LoginDto.cs
using System.ComponentModel.DataAnnotations;

namespace VehicleRegistryAPI.DTOs
{
    public class LoginDto
    {
        [Required]
        [StringLength(100)]
        public string Username { get; set; } = string.Empty;
        
        [Required]
        [StringLength(100)]
        public string Password { get; set; } = string.Empty;
    }
}

// DTOs/RegisterDto.cs
using System.ComponentModel.DataAnnotations;

namespace VehicleRegistryAPI.DTOs
{
    public class RegisterDto
    {
        [Required]
        [StringLength(100, MinimumLength = 3)]
        public string Username { get; set; } = string.Empty;
        
        [Required]
        [StringLength(100, MinimumLength = 12)]
        [RegularExpression(@"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^\da-zA-Z]).{12,}$")]
        public string Password { get; set; } = string.Empty;
        
        [StringLength(50)]
        public string Role { get; set; } = "Editor";
    }
}

// DTOs/VehicleDto.cs
using System.ComponentModel.DataAnnotations;

namespace VehicleRegistryAPI.DTOs
{
    public class VehicleDto
    {
        [Required]
        [StringLength(7, MinimumLength = 7)]
        [RegularExpression(@"^[A-Z]{3}[0-9][A-Z0-9][0-9]{2}$")]
        public string LicensePlate { get; set; } = string.Empty;
        
        [Required]
        [StringLength(100)]
        public string Brand { get; set; } = string.Empty;
        
        [Required]
        [StringLength(100)]
        public string Model { get; set; } = string.Empty;
        
        [Required]
        [Range(1886, 2100)]
        public int Year { get; set; }
        
        [Required]
        [StringLength(50)]
        public string Color { get; set; } = string.Empty;
    }
}

// DTOs/AuthResponseDto.cs
namespace VehicleRegistryAPI.DTOs
{
    public class AuthResponseDto
    {
        public string Token { get; set; } = string.Empty;
        public string RefreshToken { get; set; } = string.Empty;
        public DateTime Expires { get; set; }
        public string Username { get; set; } = string.Empty;
        public string Role { get; set; } = string.Empty;
        public bool ForcePasswordReset { get; set; }
    }
}