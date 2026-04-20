using Avalonia;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Data.Core;
using Avalonia.Data.Core.Plugins;
using System.Linq;
using Avalonia.Markup.Xaml;
using SecureHub.Client.ViewModels;
using SecureHub.Client.Views;

using Avalonia.Controls;

namespace SecureHub.Client;

public partial class App : Application
{
    /// <summary>
    /// Exposes the current top-level visual root so ViewModels can access platform dialogs (FilePicker).
    /// </summary>
    public static Control? CurrentMainView { get; set; }
    public override void Initialize()
    {
        AvaloniaXamlLoader.Load(this);

        // DEFAULT FALLBACK IN CASE RESOURCE FAILS
        var apiBaseUrl = "https://localhost:443";
        // SECURITY PHASE 7: Dynamic Dev Environment Binding (No Hardcoding)
        try
        {
            if (System.OperatingSystem.IsBrowser())
            {
                // In Docker/production, Nginx serves WASM and proxies /api/ on the SAME origin.
                // Use the browser's current location as the API base to eliminate CORS entirely.
                var origin = GetBrowserOrigin();
                if (!string.IsNullOrEmpty(origin))
                {
                    apiBaseUrl = origin;
                }
            }
            else
            {
                var assembly = typeof(App).Assembly;
                using var stream = assembly.GetManifestResourceStream("SecureHub.Client.appsettings.json");
                if (stream != null)
                {
                    using var reader = new System.IO.StreamReader(stream);
                    var json = reader.ReadToEnd();
                    var doc = System.Text.Json.JsonDocument.Parse(json);
                    var config = doc.RootElement.GetProperty("ApiConfig");

                    apiBaseUrl = System.OperatingSystem.IsAndroid() 
                        ? config.GetProperty("AndroidHost").GetString()! 
                        : config.GetProperty("DefaultHost").GetString()!;
                }
            }
        }
        catch
        {
            // Swallow parsing errors to prevent UI crash
        }
        finally
        {
            Services.ApiClient.Initialize(apiBaseUrl);
        }
    }

    /// <summary>
    /// Reads the browser's current origin (protocol + host + port) via JavaScript interop.
    /// Returns null on non-browser platforms.
    /// </summary>
    private static string? GetBrowserOrigin()
    {
        try
        {
            // Use .NET WASM JS interop to read window.location.origin
            var jsRuntime = System.Runtime.InteropServices.JavaScript.JSHost.GlobalThis;
            var location = jsRuntime.GetPropertyAsJSObject("location");
            return location?.GetPropertyAsString("origin");
        }
        catch
        {
            return null;
        }
    }

    public override void OnFrameworkInitializationCompleted()
    {
        if (ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop)
        {
            var window = new MainWindow { DataContext = new MainViewModel() };
            desktop.MainWindow = window;
            CurrentMainView = window;
        }
        else if (ApplicationLifetime is IActivityApplicationLifetime singleViewFactoryApplicationLifetime)
        {
            singleViewFactoryApplicationLifetime.MainViewFactory = () =>
            {
                var view = new MainView { DataContext = new MainViewModel() };
                CurrentMainView = view;
                return view;
            };
        }
        else if (ApplicationLifetime is ISingleViewApplicationLifetime singleViewPlatform)
        {
            var view = new MainView { DataContext = new MainViewModel() };
            singleViewPlatform.MainView = view;
            CurrentMainView = view;
        }

        base.OnFrameworkInitializationCompleted();
    }
}