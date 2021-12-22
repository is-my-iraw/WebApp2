using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using WebApp2.Data;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
var connectionString = builder.Configuration.GetConnectionString("DefaultConnection");
builder.Services.AddDbContext<WebApp2Context>(options =>
    options.UseSqlite(connectionString));builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlServer(connectionString));
builder.Services.AddDatabaseDeveloperPageExceptionFilter();

builder.Services.AddDefaultIdentity<IdentityUser>(options => options.SignIn.RequireConfirmedAccount = true)
    .AddEntityFrameworkStores<ApplicationDbContext>();
builder.Services.AddRazorPages();

var services = builder.Services;
var configuration = builder.Configuration;

services.AddAuthentication()
    .AddGoogle(googleOptions =>
    {
        // Đọc thông tin Authentication:Google từ appsettings.json
        IConfigurationSection googleAuthNSection = configuration.GetSection("Authentication:Google");

        // Thiết lập ClientID và ClientSecret để truy cập API google
        googleOptions.ClientId = googleAuthNSection["ClientId"];
        googleOptions.ClientSecret = googleAuthNSection["ClientSecret"];
        // Cấu hình Url callback lại từ Google (không thiết lập thì mặc định là /signin-google)
        googleOptions.CallbackPath = "/dang-nhap-tu-google";

    })
    .AddFacebook(facebookOptions => {
        // Đọc cấu hình
        IConfigurationSection facebookAuthNSection = configuration.GetSection("Authentication:Facebook");
        facebookOptions.AppId = facebookAuthNSection["AppId"];
        facebookOptions.AppSecret = facebookAuthNSection["AppSecret"];
        // Thiết lập đường dẫn Facebook chuyển hướng đến
        facebookOptions.CallbackPath = "/dang-nhap-tu-facebook";
    })
    .AddMicrosoftAccount(microsoftOptions =>
     {
         IConfigurationSection microsoftAuthNSection = configuration.GetSection("Authentication:Microsoft");
         microsoftOptions.ClientId = microsoftAuthNSection["ClientId"];
         microsoftOptions.ClientSecret = microsoftAuthNSection["ClientSecret"];
         // Cấu hình Url callback lại từ Google (không thiết lập thì mặc định là /signin-google)
         microsoftOptions.CallbackPath = "/signin-microsoft";
     });

builder.Services.Configure<IdentityOptions>(options =>
{
    // Password settings.
    options.Password.RequireDigit = true;
    options.Password.RequireLowercase = true;
    options.Password.RequireNonAlphanumeric = true;
    options.Password.RequireUppercase = true;
    options.Password.RequiredLength = 6;
    options.Password.RequiredUniqueChars = 1;

    // Lockout settings.
    options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(5);
    options.Lockout.MaxFailedAccessAttempts = 5;
    options.Lockout.AllowedForNewUsers = true;

    // User settings.
    options.User.AllowedUserNameCharacters =
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._@+";
    options.User.RequireUniqueEmail = false;
});

builder.Services.ConfigureApplicationCookie(options =>
{
    // Cookie settings
    options.Cookie.HttpOnly = true;
    options.ExpireTimeSpan = TimeSpan.FromMinutes(5);

    options.LoginPath = "/Identity/Account/Login";
    options.AccessDeniedPath = "/Identity/Account/AccessDenied";
    options.SlidingExpiration = true;
});

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseMigrationsEndPoint();
}
else
{
    app.UseExceptionHandler("/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();

app.UseDeveloperExceptionPage();

app.MapRazorPages();

app.Run();
