using System.Windows;
using System.Windows.Controls;
using DokuVault.Scanner.ViewModels;

namespace DokuVault.Scanner.Infrastructure;

/// <summary>Picks the editor for a form field by its kind (FieldViewModel.Editor).</summary>
public sealed class FieldTemplateSelector : DataTemplateSelector
{
    public DataTemplate? Text { get; set; }
    public DataTemplate? Multiline { get; set; }
    public DataTemplate? Choice { get; set; }
    public DataTemplate? Bool { get; set; }
    public DataTemplate? Date { get; set; }

    public override DataTemplate? SelectTemplate(object item, DependencyObject container) =>
        item is not FieldViewModel field
            ? null
            : field.Editor switch
            {
                "multiline" => Multiline,
                "choice" => Choice,
                "bool" => Bool,
                "date" => Date,
                _ => Text,
            };
}
