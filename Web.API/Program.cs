using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Serilog;
using Serilog.Events;
using Serilog.Filters;
using Web.API.Features.Authentication;
using Web.API.Features.Authentication.Commands;
using Web.API.Features.Authentication.Models;
using Web.API.Features.Authentication.Queries;
using Web.API.Features.Authentication.Services;
using Web.API.Infrastructure.DbContexts;
using Web.API.Initialization;

var builder = WebApplication.CreateBuilder(args);

// Add Services to the Builder
if (builder.Environment.IsDevelopment())
{
    builder.Services.AddSingleton<IEmailService, EmailServiceDummy>();
}
else
{
    // Register real email service for production
    builder.Services.AddSingleton<IEmailService, EmailServiceDummy>(); // TODO: Update after creating production email implementation. 
}

builder.Services.AddDbContext<ApplicationDbContext>(options =>
options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));

builder.Services.AddIdentity<ApplicationUser, ApplicationRole>(options =>
{
    options.SignIn.RequireConfirmedEmail = true;
})
    .AddEntityFrameworkStores<ApplicationDbContext>()
    .AddDefaultTokenProviders();


builder.Services.AddSingleton<IHttpContextAccessor, HttpContextAccessor>();

// Configure application cookie
builder.Services.ConfigureApplicationCookie(config =>
{
    config.Cookie.HttpOnly = true;
    config.Cookie.SecurePolicy = CookieSecurePolicy.Always;
    config.ExpireTimeSpan = TimeSpan.FromHours(4);
    config.SlidingExpiration = true;

    config.Events = new CookieAuthenticationEvents
    {
        OnRedirectToLogin = context =>
        {
            context.Response.StatusCode = 401;
            return Task.CompletedTask;
        }
    };
});

// Register Authentication related commands and services
builder.Services.AddTransient<IIdentityService, IdentityService>();
builder.Services.AddTransient<RegisterCommand>();
builder.Services.AddTransient<LoginCommand>();
builder.Services.AddTransient<LogoutCommand>();
builder.Services.AddTransient<GetUserQuery>();
builder.Services.AddTransient<GetUserByEmailQuery>();
builder.Services.AddTransient<GetUserRolesQuery>();
builder.Services.AddTransient<VerifyUserEmailCommand>();
builder.Services.AddTransient<SendEmailVerificationEmailCommand>();
builder.Services.AddTransient<AddUserToRoleCommand>();
builder.Services.AddTransient<RemoveUserFromRoleCommand>();
builder.Services.AddTransient<RequestPasswordResetCommand>();
builder.Services.AddTransient<ResetUserPasswordCommand>();
builder.Services.AddTransient<ChangeUserPasswordCommand>();
builder.Services.AddTransient<AddUserPhoneCommand>();
builder.Services.AddTransient<RemoveUserPhoneCommand>();
builder.Services.AddTransient<UpdateUserPhoneCommand>();
builder.Services.AddTransient<AddUserAddressCommand>();
builder.Services.AddTransient<RemoveUserAddressCommand>();
builder.Services.AddTransient<UpdateUserAddressCommand>();

builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

Log.Logger = new LoggerConfiguration()
    .MinimumLevel.Verbose()
    .MinimumLevel.Override("Microsoft", LogEventLevel.Information)
    .Enrich.FromLogContext()
    .WriteTo.Console(restrictedToMinimumLevel: LogEventLevel.Warning)
    .WriteTo.Logger(lc => lc
        .Filter.ByIncludingOnly(Matching.FromSource<IdentityService>())
        .WriteTo.File("logs/identityService.txt", rollingInterval: RollingInterval.Day))
    .WriteTo.Logger(lc => lc
        .Filter.ByIncludingOnly(Matching.FromSource<AuthenticationController>())
        .WriteTo.File("logs/authenticationController.txt", rollingInterval: RollingInterval.Day))
    .WriteTo.File("logs/myapp.txt", rollingInterval: RollingInterval.Day)
    .WriteTo.File("logs/errors.txt", rollingInterval: RollingInterval.Day, restrictedToMinimumLevel: LogEventLevel.Error)
    .CreateLogger();
builder.Logging.AddSerilog(Log.Logger);

var app = builder.Build();

using (var scope = app.Services.CreateScope())
{
    var roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<ApplicationRole>>();
    RoleSeed.EnsureCreatedAsync(roleManager).GetAwaiter().GetResult();

    var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
    var dbContext = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
    UserSeed.EnsureCreatedAsync(userManager, roleManager, dbContext).GetAwaiter().GetResult();
}

// Configure the HTTP request pipeline.
app.UseHttpsRedirection();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

// Add redirection to Swagger UI as the default endpoint
app.MapFallback(async context =>
{
    var path = context.Request.Path.Value;

    // List of paths that should not be redirected to Swagger
    var excludedPaths = new List<string>
    {
        "/api", // Assuming your APIs are under the /api route
        // Add other paths as needed
    };

    // Check if the requested path starts with any of the excluded paths
    if (!excludedPaths.Any(p => path.StartsWith(p, StringComparison.OrdinalIgnoreCase)))
    {
        // If not, redirect to Swagger UI
        context.Response.Redirect("/swagger");
    }
    else
    {
        // If yes, let the request proceed normally
        await Task.CompletedTask;
    }
});

app.Run();
