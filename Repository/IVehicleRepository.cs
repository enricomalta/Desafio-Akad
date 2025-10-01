// Repository/IVehicleRepository.cs
using VehicleRegistryAPI.Models;
using System.Collections.Generic;
using System.Threading.Tasks;

// Repository/VehicleRepository.cs
using Microsoft.EntityFrameworkCore;
using VehicleRegistryAPI.Data;

namespace VehicleRegistryAPI.Repository
{
    public interface IVehicleRepository
    {
        Task<IEnumerable<Vehicle>> GetAllAsync();
        Task<Vehicle?> GetByIdAsync(int id);
        Task<Vehicle?> GetByLicensePlateAsync(string licensePlate);
        Task<Vehicle> CreateAsync(Vehicle vehicle);
        Task<Vehicle> UpdateAsync(Vehicle vehicle);
        Task DeleteAsync(int id);
        Task<bool> ExistsAsync(string licensePlate);
    }
}

namespace VehicleRegistryAPI.Repository
{
    public class VehicleRepository : IVehicleRepository
    {
        private readonly ApplicationDbContext _context;

        public VehicleRepository(ApplicationDbContext context)
        {
            _context = context;
        }

        public async Task<IEnumerable<Vehicle>> GetAllAsync()
        {
            return await _context.Vehicles.ToListAsync();
        }

        public async Task<Vehicle?> GetByIdAsync(int id)
        {
            return await _context.Vehicles.FindAsync(id);
        }

        public async Task<Vehicle?> GetByLicensePlateAsync(string licensePlate)
        {
            return await _context.Vehicles
                .FirstOrDefaultAsync(v => v.LicensePlate == licensePlate.ToUpper());
        }

        public async Task<Vehicle> CreateAsync(Vehicle vehicle)
        {
            vehicle.LicensePlate = vehicle.LicensePlate.ToUpper();
            _context.Vehicles.Add(vehicle);
            await _context.SaveChangesAsync();
            return vehicle;
        }

        public async Task<Vehicle> UpdateAsync(Vehicle vehicle)
        {
            vehicle.LicensePlate = vehicle.LicensePlate.ToUpper();
            vehicle.UpdatedAt = DateTime.UtcNow;
            _context.Vehicles.Update(vehicle);
            await _context.SaveChangesAsync();
            return vehicle;
        }

        public async Task DeleteAsync(int id)
        {
            var vehicle = await _context.Vehicles.FindAsync(id);
            if (vehicle != null)
            {
                _context.Vehicles.Remove(vehicle);
                await _context.SaveChangesAsync();
            }
        }

        public async Task<bool> ExistsAsync(string licensePlate)
        {
            return await _context.Vehicles
                .AnyAsync(v => v.LicensePlate == licensePlate.ToUpper());
        }
    }
}