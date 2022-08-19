using System;
using System.Collections.Generic;
using System.Linq;
using System.Linq.Expressions;
using System.Text.RegularExpressions;
using Lambda2Js;

namespace MT.Blazor.IndexedDB.Extensions;

internal static class ExpressionExtensions
{
    private static readonly Regex PascalToCamelCasePropertyName = new(@"\.[A-Z]");
    
    public static IEnumerable<string> ToJavascriptCode<T>(this Expression<Func<T, bool>>[] predicates)
    {
        if (!(predicates?.Any(p => p != null) ?? false))
        {
            return null;
        }
            
        return predicates.Select(ToJavascriptCode);
    }

    private static string ToJavascriptCode<T>(this Expression<Func<T, bool>> predicate)
    {
        if (predicate == null)
        {
            return null;
        }

        var jsCode = predicate.CompileToJavascript(new JavascriptCompilationOptions((JsCompilationFlags) 0, new CustomJavascriptConversionExtension()));

        return PascalToCamelCasePropertyName.Replace(jsCode, m => m.ToString().ToLower());
    }
}