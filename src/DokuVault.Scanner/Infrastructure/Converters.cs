using System.Globalization;
using System.Windows;
using System.Windows.Data;

namespace DokuVault.Scanner.Infrastructure;

public sealed class Inverse : IValueConverter
{
    public static readonly Inverse Instance = new();

    public object Convert(object value, Type targetType, object parameter, CultureInfo culture) => value is not true;

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) => value is not true;
}

/// <summary>Visible when the value is null or empty - for empty states.</summary>
public sealed class VisibleWhenEmpty : IValueConverter
{
    public static readonly VisibleWhenEmpty Instance = new();

    public object Convert(object? value, Type targetType, object parameter, CultureInfo culture) =>
        value is null || value is string { Length: 0 } || value is 0 ? Visibility.Visible : Visibility.Collapsed;

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) =>
        throw new NotSupportedException();
}

/// <summary>Visible when the value is set.</summary>
public sealed class VisibleWhenSet : IValueConverter
{
    public static readonly VisibleWhenSet Instance = new();

    public object Convert(object? value, Type targetType, object parameter, CultureInfo culture) =>
        value is null || value is string { Length: 0 } || value is 0 || value is false ? Visibility.Collapsed : Visibility.Visible;

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) =>
        throw new NotSupportedException();
}
