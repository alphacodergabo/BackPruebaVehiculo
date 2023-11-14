using Domain;
using FluentValidation.AspNetCore;
using IT_APP;
using MediatR;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.HttpsPolicy;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Authorization;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using Persistence;
using Security.SecurityToken;
using Security.SecurityToken.Contracts;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using USER_APP;
using static IT_APP.Login;

namespace ProjectVehicles
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            string encryptionKid = Configuration["secretKey"];
            services.AddDbContext<AplicationContext>(opt => {
                opt.UseSqlServer(Configuration.GetConnectionString("DefaultConnection"),
                    sqlServerOptions => sqlServerOptions.CommandTimeout(360));
            });
            services.AddMediatR(typeof(Login.Manejador).Assembly);
            services.AddMediatR(typeof(GetUserInfo.Manejado).Assembly);
            services.AddControllers().AddNewtonsoftJson(options =>
           options.SerializerSettings.ReferenceLoopHandling = Newtonsoft.Json.ReferenceLoopHandling.Ignore
           );
            services.AddCors(options =>
            {
                options.AddDefaultPolicy(
                    builder => builder.WithOrigins( "http://localhost:4200")
                );
            });
            var builder = services.AddIdentityCore<User>();
            var identityBuilder = new IdentityBuilder(builder.UserType, builder.Services);
            identityBuilder.AddEntityFrameworkStores<AplicationContext>();
            identityBuilder.AddSignInManager<SignInManager<User>>();
            services.TryAddSingleton<ISystemClock, SystemClock>();
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(encryptionKid.ToString()));
            services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme).AddJwtBearer(opt => {
                opt.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidIssuer = "issuer",
                    ValidAudience = "audience",
                    ValidateIssuerSigningKey = true,
                    ValidateLifetime = true,
                    RequireExpirationTime = true,
                    ValidateIssuer = true,
                    ValidateAudience = true,
                    IssuerSigningKey = key,
                    TokenDecryptionKey = key,
                    ClockSkew = TimeSpan.Zero
                };
            });
            services.AddScoped<IJwtGenerador, JwtGenerator>();
            services.AddScoped<IUsuarioSesion, UsuarioSesion>();
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            app.UseAuthentication();

            app.UseHttpsRedirection();

            app.UseRouting();

            app.UseCors(options => options.AllowAnyOrigin().AllowAnyMethod().AllowAnyHeader());

            app.UseAuthorization();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllers();
            });
        }
    }
}
