using Microsoft.AspNetCore.Identity;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations.Schema;
using System.Text;

namespace Domain
{
    public class User : IdentityUser
    {
        [Column(TypeName = "varchar(100)")]
        public string Name { get; set; }
        [Column(TypeName = "varchar(100)")]
        public string LastName { get; set; }
        [Column(TypeName = "char(8)")]
        public string Doc { get; set; }
        [Column(TypeName = "char(8)")]
        public string DriverLicence { get; set; }
        public bool Active { get; set; }
        [Column(TypeName = "varchar(20)")]
        public string RegistrationUser { get; set; }
        public DateTime RegistrationDate { get; set; }
        [Column(TypeName = "varchar(20)")]
        public string ModificationUser { get; set; }
        public Nullable<DateTime> ModificationDate { get; set; }
        public ICollection<Vehicle> Vehicle { get; set; }
    }
}
