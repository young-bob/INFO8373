using System;
using System.Collections.Generic;
using System.Linq;
using System.Collections.ObjectModel;
using System.IO;
using System.Threading.Tasks;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Platform.Storage;
using Avalonia.Input.Platform;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using SecureHub.Client.Services;

namespace SecureHub.Client.ViewModels;

public partial class DashboardViewModel : ViewModelBase
{
    private readonly MainViewModel _router;

    [ObservableProperty]
    private ObservableCollection<FileItemDto> _files = new();
    
    [ObservableProperty]
    private ObservableCollection<ShareLinkDto> _activeShares = new();

    [ObservableProperty]
    private string _statusMessage = "";

    [ObservableProperty]
    private bool _isLoading;

    public Avalonia.Platform.Storage.IStorageProvider? StorageProvider { get; set; }

    private Avalonia.Platform.Storage.IStorageProvider? GetActiveStorageProvider()
    {
        if (Application.Current?.ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop)
        {
            return desktop.MainWindow?.StorageProvider;
        }
        if (Application.Current?.ApplicationLifetime is ISingleViewApplicationLifetime browser)
        {
            return TopLevel.GetTopLevel(browser.MainView)?.StorageProvider;
        }
        return StorageProvider;
    }

    // Download path
    [ObservableProperty]
    private string _downloadFolderPath = "";

    // Share dialog state
    [ObservableProperty]
    private bool _isShareDialogVisible;

    [ObservableProperty]
    private int _shareFileId;

    // Strong GC roots to prevent macOS libAvaloniaNative block callback EXC_BAD_ACCESS
    private Task<IReadOnlyList<IStorageFile>>? _activeOpenTask;
    private Task<IStorageFile?>? _activeSaveTask;

    [ObservableProperty]
    private string _sharePassword = "";

    [ObservableProperty]
    private int _sharePermissionIndex = 1; // 1 = Download, 0 = View

    [ObservableProperty]
    private int _shareExpiryMinutes = 60;

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(ConfirmShareCommand))]
    [NotifyPropertyChangedFor(nameof(IsShareCreated))]
    [NotifyPropertyChangedFor(nameof(CloseButtonText))]
    private string _shareResultToken = "";

    public bool IsShareCreated => !string.IsNullOrWhiteSpace(ShareResultToken);
    public string CloseButtonText => IsShareCreated ? "Close" : "Cancel";

    // Delete account state
    [ObservableProperty]
    private bool _isDeleteAccountVisible;

    [ObservableProperty]
    private string _deleteAccountPassword = "";

    public DashboardViewModel(MainViewModel router)
    {
        _router = router;
        // StorageProvider dynamically handles native file boundaries, no hardcoded paths needed.
        _downloadFolderPath = "StorageProvider Managed";
        _ = LoadFilesAsync();
    }

    [RelayCommand]
    public async Task LoadFilesAsync()
    {
        try
        {
            IsLoading = true;
            StatusMessage = "";
            var fetched = await ApiClient.Instance.GetMyFilesAsync();
            Files.Clear();
            foreach (var f in fetched) Files.Add(f);
        }
        catch (Exception ex)
        {
            StatusMessage = $"Failed to load files: {ex.Message}";
        }
        finally
        {
            IsLoading = false;
        }
    }

    // ==================== Upload (StorageProvider / Stream) ====================

    [RelayCommand]
    public async Task OpenFilePickerAsync()
    {
        var sp = GetActiveStorageProvider();
        if (sp == null) return;

        var options = new Avalonia.Platform.Storage.FilePickerOpenOptions
        {
            Title = "Select File to Encrypt and Upload",
            AllowMultiple = false
        };

        // Pin the task to GC root
        _activeOpenTask = sp.OpenFilePickerAsync(options);
        var files = await _activeOpenTask;
        _activeOpenTask = null;

        if (files.Count > 0)
        {
            await using var stream = await files[0].OpenReadAsync();
            await ProcessFileStreamAsync(stream, files[0].Name);
        }
    }

    public async Task ProcessFileStreamAsync(System.IO.Stream stream, string fileName)
    {
        try
        {
            IsLoading = true;
            StatusMessage = "Encrypting and uploading...";

            var (success, msg) = await ApiClient.Instance.UploadFileAsync(stream, fileName, null);
            StatusMessage = msg;

            if (success) await LoadFilesAsync();
        }
        catch (Exception ex)
        {
            StatusMessage = $"Upload failed: {ex.Message}";
        }
        finally
        {
            IsLoading = false;
        }
    }

    // ==================== Download (direct to Downloads folder) ====================

    [RelayCommand]
    public async Task DownloadFileAsync(int fileId)
    {
        try
        {
            IsLoading = true;
            StatusMessage = "Decrypting and downloading...";

            var sp = GetActiveStorageProvider();
            if (sp == null)
            {
                StatusMessage = "Storage interface unavailable.";
                return;
            }

            // [SECURITY FIX] File Picker MUST be invoked immediately after user click. 
            // Awaiting long network operations first will expire the Browser's Transient User Activation token!
            var fileDto = Files.FirstOrDefault(f => f.Id == fileId);
            var suggestedName = fileDto?.FileName ?? "vault_decrypted_file.dat";
            var defaultExt = Path.GetExtension(suggestedName)?.TrimStart('.') ?? "dat";
            if (string.IsNullOrEmpty(defaultExt)) defaultExt = "dat";

            var options = new Avalonia.Platform.Storage.FilePickerSaveOptions
            {
                Title = "Save Decrypted File",
                SuggestedFileName = suggestedName,
                DefaultExtension = defaultExt
            };

            // Pin the task to GC root
            _activeSaveTask = sp.SaveFilePickerAsync(options);
            var file = await _activeSaveTask;
            _activeSaveTask = null;

            if (file == null)
            {
                IsLoading = false;
                StatusMessage = "Download cancelled.";
                return;
            }

            // Now perform the potentially slow HTTP fetching protocol
            var (success, dataStream, fileName) = await ApiClient.Instance.DownloadFileAsync(fileId);
            if (!success || dataStream == null)
            {
                StatusMessage = "Download failed from server.";
                return;
            }

            await using var fs = await file.OpenWriteAsync();
            await dataStream.CopyToAsync(fs);
            StatusMessage = $"Saved: {file.Name}";

            dataStream.Dispose();
        }
        catch (Exception ex)
        {
            StatusMessage = $"Download failed: {ex.Message}";
        }
        finally
        {
            IsLoading = false;
        }
    }

    // ==================== Delete File ====================

    [RelayCommand]
    public async Task DeleteFileAsync(int fileId)
    {
        try
        {
            IsLoading = true;
            var (success, msg) = await ApiClient.Instance.DeleteFileAsync(fileId);
            StatusMessage = msg;
            if (success) await LoadFilesAsync();
        }
        catch (Exception ex)
        {
            StatusMessage = $"Delete failed: {ex.Message}";
        }
        finally
        {
            IsLoading = false;
        }
    }

    // ==================== Share Dialog ====================

    [RelayCommand]
    public void OpenShareDialog(int fileId)
    {
        ShareFileId = fileId;
        SharePassword = "";
        SharePermissionIndex = 1;
        ShareExpiryMinutes = 60;
        ShareResultToken = "";
        IsShareDialogVisible = true;
        _ = LoadActiveSharesAsync();
    }
    
    public async Task LoadActiveSharesAsync()
    {
        try
        {
            var links = await ApiClient.Instance.GetActiveSharesAsync(ShareFileId);
            ActiveShares.Clear();
            foreach (var link in links) ActiveShares.Add(link);
        }
        catch { }
    }
    
    [RelayCommand]
    public async Task RevokeShareAsync(int shareId)
    {
        try
        {
            var (success, msg) = await ApiClient.Instance.RevokeShareLinkAsync(shareId);
            StatusMessage = msg;
            if (success) await LoadActiveSharesAsync();
        }
        catch (Exception ex)
        {
            StatusMessage = $"Revoke error: {ex.Message}";
        }
    }

    private bool CanConfirmShare() => string.IsNullOrWhiteSpace(ShareResultToken);

    [RelayCommand(CanExecute = nameof(CanConfirmShare))]
    public async Task ConfirmShareAsync()
    {
        try
        {
            string shareOption = SharePermissionIndex == 0 ? "View" : "Download";
            var (success, token, msg) = await ApiClient.Instance.CreateShareLinkAsync(
                ShareFileId, ShareExpiryMinutes, string.IsNullOrWhiteSpace(SharePassword) ? null : SharePassword, shareOption);

            if (success)
            {
                var url = $"{ApiClient.Instance.BaseUrl}/api/shares/{token}";
                
                ShareResultToken = url;
                StatusMessage = "Share link created! (Remember to send the password separately)";
                await LoadActiveSharesAsync();
            }
            else
            {
                StatusMessage = msg;
            }
        }
        catch (Exception ex)
        {
            StatusMessage = $"Share failed: {ex.Message}";
        }
    }

    [RelayCommand]
    public void CloseShareDialog()
    {
        IsShareDialogVisible = false;
    }

    [RelayCommand]
    public async Task CopyShareLinkAsync()
    {
        try
        {
            if (App.CurrentMainView != null && !string.IsNullOrWhiteSpace(ShareResultToken))
            {
                var topLevel = TopLevel.GetTopLevel(App.CurrentMainView);
                var clipboard = topLevel?.Clipboard;
                if (clipboard != null)
                {
                    await clipboard.SetTextAsync(ShareResultToken);
                    StatusMessage = "Successfully copied link to clipboard!";
                }
            }
        }
        catch (Exception ex)
        {
            StatusMessage = $"Copy failed: {ex.Message}";
        }
    }

    [RelayCommand]
    public async Task CopyExistingShareLinkAsync(ShareLinkDto share)
    {
        try
        {
            if (share == null || string.IsNullOrWhiteSpace(share.Token)) return;
            
            var url = $"{ApiClient.Instance.BaseUrl}/api/shares/{share.Token}";
            
            if (App.CurrentMainView != null)
            {
                var topLevel = TopLevel.GetTopLevel(App.CurrentMainView);
                var clipboard = topLevel?.Clipboard;
                if (clipboard != null)
                {
                    await clipboard.SetTextAsync(url);
                    StatusMessage = share.HasPassword 
                        ? "URL Copied. (Note: The recipient will need the password you previously set)" 
                        : "URL Copied to clipboard!";
                }
            }
        }
        catch (Exception ex)
        {
            StatusMessage = $"Copy failed: {ex.Message}";
        }
    }

    // ==================== Account Deletion ====================

    [RelayCommand]
    public void ShowDeleteAccount()
    {
        DeleteAccountPassword = "";
        IsDeleteAccountVisible = true;
    }

    [RelayCommand]
    public async Task ConfirmDeleteAccountAsync()
    {
        try
        {
            if (string.IsNullOrWhiteSpace(DeleteAccountPassword)) return;

            var (success, msg) = await ApiClient.Instance.EraseAccountAsync(DeleteAccountPassword);
            StatusMessage = msg;
            if (success)
            {
                IsDeleteAccountVisible = false;
                _router.NavigateTo(new LoginViewModel(_router));
            }
        }
        catch (Exception ex)
        {
            StatusMessage = $"Account deletion failed: {ex.Message}";
        }
    }

    [RelayCommand]
    public void CancelDeleteAccount()
    {
        IsDeleteAccountVisible = false;
    }

    // ==================== Logout ====================

    [RelayCommand]
    public async Task LogoutAsync()
    {
        try
        {
            await ApiClient.Instance.LogoutAsync();
        }
        catch
        {
            // Swallow - navigate to login regardless
        }
        _router.NavigateTo(new LoginViewModel(_router));
    }
}
