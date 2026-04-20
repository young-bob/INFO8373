using Avalonia.Controls;
using SecureHub.Client.ViewModels;

namespace SecureHub.Client.Views;

public partial class DashboardView : UserControl
{
    public DashboardView()
    {
        InitializeComponent();
    }

    protected override void OnAttachedToVisualTree(Avalonia.VisualTreeAttachmentEventArgs e)
    {
        base.OnAttachedToVisualTree(e);
        if (DataContext is DashboardViewModel vm)
        {
            var topLevel = TopLevel.GetTopLevel(this);
            if (topLevel != null)
            {
                vm.StorageProvider = topLevel.StorageProvider;
            }
        }
    }
}
