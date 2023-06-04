using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Text;

namespace Domain
{
    public class Vehicle
    {
        [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
        [Key, Column(Order = 0)]
        public int VehicleId { get; set; }
        [Column(TypeName = "varchar(50)")]
        public string Brand { get; set; }
        public string Model { get; set; }
        public int Power { get; set; }
        [Column(TypeName = "varchar(2)")]
        public string Category { get; set; }
        [Column(TypeName = "varchar(20)")]
        public string Color { get; set; }
        public int DoorsPassenger { get; set; }
        [Column(TypeName = "varchar(50)")]
        public string RegistrationPlate { get; set; }
        [Column(TypeName = "varchar(20)")]
        public string Fuel { get; set; }
        public bool Active { get; set; }
        public string Id { get; set; }
        public User Usuario { get; set; }
        [Column(TypeName = "varchar(20)")]
        public string RegistrationUser { get; set; }
        public DateTime RegistrationDate { get; set; }
        [Column(TypeName = "varchar(20)")]
        public string ModificationUser { get; set; }
        public Nullable<DateTime> ModificationDate { get; set; }
    }
}
