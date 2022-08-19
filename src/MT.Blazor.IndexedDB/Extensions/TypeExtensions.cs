using System;
using System.Linq.Expressions;

namespace MT.Blazor.IndexedDB.Extensions;

internal static class TypeExtensions
{
    private const string FieldExpressionClassName = "FieldExpression";
    private const string PropertyExpressionClassName = "PropertyExpression";
    private const string TypedParameterExpressionClassName = "TypedParameterExpression";
    
    public static bool IsArrayOf<T>(this Type type)
    {
        return type == typeof (T[]);
    }

    public static string FirstToLower(this string input)
    {
        if (input != string.Empty && char.IsUpper(input[0]))
        {
            input = char.ToLower(input[0]) + input[1..];
        }

        return input;
    }

    public static bool IsFieldExpression(this Expression expression)
    {
        return expression?.GetType().FullName?.EndsWith(FieldExpressionClassName) ?? false;
    }

    public static bool IsPropertyExpression(this Expression expression)
    {
        return expression?.GetType().FullName?.EndsWith(PropertyExpressionClassName) ?? false;
    }
    
    public static bool IsTypedParameterExpression(this Expression expression)
    {
        return expression?.GetType().FullName?.EndsWith(TypedParameterExpressionClassName) ?? false;
    }
}