using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Interop;
using Microsoft.Win32;

namespace DokuVault.Scanner.Infrastructure;

public enum ThemeMode
{
    System,
    Light,
    Dark,
}

/// <summary>
/// Light or dark: swaps the colour dictionary (Themes/Light.xaml or
/// Themes/Dark.xaml, always the first merged dictionary of the app) and
/// darkens the Windows title bar. "System" follows the Windows setting
/// "App mode", also while the app runs.
/// </summary>
public static class ThemeManager
{
    private const string PersonalizeKey = @"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize";
    private static bool _listening;

    public static ThemeMode Mode { get; private set; } = ThemeMode.System;

    public static bool IsDark { get; private set; }

    /// <summary>Raised after every change of the colours.</summary>
    public static event Action? Changed;

    public static void Apply(ThemeMode mode)
    {
        Mode = mode;
        bool dark = mode == ThemeMode.Dark || (mode == ThemeMode.System && SystemPrefersDark());
        var app = Application.Current;
        if (app is null)
            return;

        var source = new Uri($"pack://application:,,,/DokuVaultScanner;component/Themes/{(dark ? "Dark" : "Light")}.xaml");
        var dictionaries = app.Resources.MergedDictionaries;
        if (dictionaries.Count == 0)
            dictionaries.Add(new ResourceDictionary { Source = source });
        else if (dictionaries[0].Source != source)
            dictionaries[0] = new ResourceDictionary { Source = source };
        IsDark = dark;

        foreach (Window window in app.Windows)
            ApplyTitleBar(window);

        if (!_listening)
        {
            SystemEvents.UserPreferenceChanged += OnUserPreferenceChanged;
            _listening = true;
        }
        Changed?.Invoke();
    }

    /// <summary>System → light → dark → system.</summary>
    public static ThemeMode Next(ThemeMode mode) => mode switch
    {
        ThemeMode.System => ThemeMode.Light,
        ThemeMode.Light => ThemeMode.Dark,
        _ => ThemeMode.System,
    };

    public static ThemeMode Parse(string? text) =>
        Enum.TryParse<ThemeMode>(text, ignoreCase: true, out var mode) ? mode : ThemeMode.System;

    public static string Label(ThemeMode mode) => mode switch
    {
        ThemeMode.Light => "Hell",
        ThemeMode.Dark => "Dunkel",
        _ => "wie Windows",
    };

    /// <summary>Call in the window's constructor: the title bar follows from the first frame.</summary>
    public static void Attach(Window window)
    {
        window.SourceInitialized += (_, _) => ApplyTitleBar(window);
    }

    private static bool SystemPrefersDark()
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(PersonalizeKey);
            return key?.GetValue("AppsUseLightTheme") is int light && light == 0;
        }
        catch (Exception e) when (e is System.Security.SecurityException or UnauthorizedAccessException)
        {
            return false;
        }
    }

    private static void OnUserPreferenceChanged(object sender, UserPreferenceChangedEventArgs e)
    {
        if (Mode != ThemeMode.System || e.Category != UserPreferenceCategory.General)
            return;
        Application.Current?.Dispatcher.BeginInvoke(() => Apply(ThemeMode.System));
    }

    // ---- the title bar (DWM, Windows 10 1809 and later)

    [DllImport("dwmapi.dll")]
    private static extern int DwmSetWindowAttribute(IntPtr hwnd, int attribute, ref int value, int size);

    [DllImport("user32.dll")]
    private static extern IntPtr SendMessage(IntPtr hwnd, int message, IntPtr wParam, IntPtr lParam);

    private const int DwmUseImmersiveDarkMode = 20;
    private const int DwmUseImmersiveDarkModeBefore20H1 = 19;
    private const int WmNcActivate = 0x0086;

    private static void ApplyTitleBar(Window window)
    {
        var hwnd = new WindowInteropHelper(window).Handle;
        if (hwnd == IntPtr.Zero)
            return;
        int value = IsDark ? 1 : 0;
        if (DwmSetWindowAttribute(hwnd, DwmUseImmersiveDarkMode, ref value, sizeof(int)) != 0)
            DwmSetWindowAttribute(hwnd, DwmUseImmersiveDarkModeBefore20H1, ref value, sizeof(int));
        // DWM repaints the caption only on the next activation - force it.
        if (window.IsActive)
        {
            SendMessage(hwnd, WmNcActivate, IntPtr.Zero, IntPtr.Zero);
            SendMessage(hwnd, WmNcActivate, new IntPtr(1), IntPtr.Zero);
        }
    }
}
