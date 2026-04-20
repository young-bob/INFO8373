using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using SecureHub.Client.Services;
using System.Threading.Tasks;

namespace SecureHub.Client.ViewModels;

public partial class LoginViewModel : ViewModelBase
{
    private readonly MainViewModel _router;

    public LoginViewModel(MainViewModel router)
    {
        _router = router;
    }

    [ObservableProperty]
    private string _email = "";

    [ObservableProperty]
    private string _password = "";

    [ObservableProperty]
    private string _errorMessage = "";

    [ObservableProperty]
    private bool _isLoading;

    [RelayCommand]
    public async Task LoginAsync()
    {
        ErrorMessage = "";
        IsLoading = true;
        try
        {
            var (success, msg) = await ApiClient.Instance.LoginAsync(Email, Password);
            if (success)
            {
                _router.NavigateTo(new DashboardViewModel(_router));
            }
            else
            {
                ErrorMessage = msg;
            }
        }
        catch (System.Exception ex)
        {
            ErrorMessage = $"Connection failed: {ex.Message}";
        }
        finally
        {
            IsLoading = false;
        }
    }

    [RelayCommand]
    public async Task RegisterAsync()
    {
        ErrorMessage = "";
        IsLoading = true;
        try
        {
            var (success, msg) = await ApiClient.Instance.RegisterAsync(Email, Password);
            ErrorMessage = msg;
        }
        catch (System.Exception ex)
        {
            ErrorMessage = $"Connection failed: {ex.Message}";
        }
        finally
        {
            IsLoading = false;
        }
    }
}
