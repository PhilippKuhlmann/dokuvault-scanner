using System.Windows.Input;

namespace DokuVault.Scanner.Infrastructure;

public static class ThemeCommands
{
    /// <summary>Ctrl+Shift+D: straight to the other one, light or dark.</summary>
    public static ICommand Toggle { get; } =
        new RelayCommand(() => ThemeManager.Apply(ThemeManager.IsDark ? ThemeMode.Light : ThemeMode.Dark));

    /// <summary>The button in the header: like Windows → light → dark → like Windows.</summary>
    public static ICommand Cycle { get; } =
        new RelayCommand(() => ThemeManager.Apply(ThemeManager.Next(ThemeManager.Mode)));
}
