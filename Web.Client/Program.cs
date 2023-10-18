using Microsoft.AspNetCore.Components.Web;
using Microsoft.AspNetCore.Components.WebAssembly.Hosting;
using Web.Client;
using MudBlazor.Services;

var builder = WebAssemblyHostBuilder.CreateDefault(args);
builder.RootComponents.Add<App>("#app");
builder.RootComponents.Add<HeadOutlet>("head::after");

// Register Services in the Builder
builder.Services.AddTransient(sp => new HttpClient
{
    BaseAddress = new Uri(builder.HostEnvironment.BaseAddress),
    DefaultRequestHeaders =
    {
        { "credentials", "include" }
    }
});
builder.Services.AddMudServices();
builder.Services.AddApiAuthorization();

await builder.Build().RunAsync();
