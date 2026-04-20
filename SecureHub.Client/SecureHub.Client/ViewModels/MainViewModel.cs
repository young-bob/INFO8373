using CommunityToolkit.Mvvm.ComponentModel;

namespace SecureHub.Client.ViewModels;

public partial class MainViewModel : ViewModelBase
{
    [ObservableProperty]
    private ViewModelBase _currentPage = null!;

    public MainViewModel()
    {
        CurrentPage = new LoginViewModel(this);
    }

    public void NavigateTo(ViewModelBase viewModel)
    {
        CurrentPage = viewModel;
    }
}
