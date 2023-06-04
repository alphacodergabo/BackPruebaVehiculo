using Domain;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using System;
using System.Collections.Generic;
using System.Text;

namespace Persistence
{
    public class AplicationContext : IdentityDbContext<User>
    {
        public AplicationContext(DbContextOptions options) : base(options)
        {

        }
        protected override void OnModelCreating(ModelBuilder modelbuilder)
        {
            base.OnModelCreating(modelbuilder);
            modelbuilder.Entity<User>()
            .HasKey(bc => new { bc.Id });
            modelbuilder.Entity<User>()
            .HasMany(g => g.Vehicle)
            .WithOne(s => s.Usuario)
            .HasForeignKey(s => s.Id);
        }
        public DbSet<Vehicle> Vehicle { get; set; }
        public DbSet<User> User { get; set; }
    }
}
