using System;
using System.Collections.Generic;
using System.Linq;
using System.Linq.Expressions;
using Lambda2Js;

namespace MT.Blazor.IndexedDB.Extensions;

public class CustomJavascriptConversionExtension : JavascriptConversionExtension
{
	public override void ConvertToJavascript(JavascriptConversionContext context)
	{
		switch (context.Node)
		{
			case ConstantExpression cte:
				ConvertConstantToJavascript(context, cte);
				return;
			case MethodCallExpression mce:
				ConvertMethodCallToJavascript(context, mce);
				return;
			case MemberExpression me:
				ConvertMemberToJavascript(context, me);
				return;
		}
	}

	private static void ConvertMemberToJavascript(JavascriptConversionContext context, MemberExpression member)
	{
		if (member.IsTypedParameterExpression() || member.Expression.IsTypedParameterExpression() || member.Expression.IsPropertyExpression()) 
		{
			return;	
		}
		
		var value = GetFieldExpressionValue(member);
		if (value == null)
		{
			return;
		}

		context.PreventDefault();
		context.GetWriter()
			.WriteLiteralStringContent(value);
	}
	
	private static void ConvertConstantToJavascript(JavascriptConversionContext context, ConstantExpression cte)
	{
		context.PreventDefault();
		
		var value = GetExpressionValue(cte.Type, cte.Value);

		if (value is not (null or string) && !cte.Type.IsValueType)
		{
			return;
		}
		
		context.GetWriter()
			.WriteLiteralStringContent(value ?? "null");
	}

	private static void ConvertMethodCallToJavascript(JavascriptConversionContext context, MethodCallExpression methodCall)
	{
		if (methodCall.Method.DeclaringType == typeof(string))
		{
			switch (methodCall.Method.Name)
			{
				case "StartsWith":
				{
					context.PreventDefault();
					var writer = context.GetWriter();
					using (writer.Operation(JavascriptOperationTypes.Call))
					{
						context.Visitor.Visit(methodCall.Object);
						writer.Write(".StartsWith(");

						if (methodCall.Arguments[0].IsFieldExpression())
						{
							var value = GetFieldExpressionValue(methodCall.Arguments[0]);
							writer.Write(value ?? "null");
						}
						else
						{
							context.Visitor.Visit(methodCall.Arguments[0]);
						}
							
						writer.Write(")");
					}

					return;
				}
				case "EndsWith":
				{
					context.PreventDefault();
					var writer = context.GetWriter();
					using (writer.Operation(JavascriptOperationTypes.Call))
					{
						context.Visitor.Visit(methodCall.Object);
						writer.Write(".EndsWith(");

						if (methodCall.Arguments[0].IsFieldExpression())
						{
							var value = GetFieldExpressionValue(methodCall.Arguments[0]);
							writer.Write(value ?? "null");
						}
						else
						{
							context.Visitor.Visit(methodCall.Arguments[0]);
						}

						writer.Write(")");
					}

					return;
				}
			}
		}
		else if (methodCall.Method.DeclaringType == typeof(DateTime))
		{
			var value = GetFieldExpressionValue(methodCall);
			if (value == null)
			{
				return;
			}

			context.PreventDefault();
			context.GetWriter()
				.WriteLiteralStringContent(value);
		}
		else if (methodCall.Method.DeclaringType == typeof(Enumerable))
		{
			switch (methodCall.Method.Name)
			{
				case "Contains":
					{
						context.PreventDefault();
						var writer = context.GetWriter();
						using (writer.Operation(JavascriptOperationTypes.Call))
						{
							using (writer.Operation(JavascriptOperationTypes.IndexerProperty))
							{
								// public static IEnumerable<TResult> Select<TSource, TResult>(this IEnumerable<TSource> source, Func<TSource, TResult> selector)
								// public static IEnumerable<TResult> Select<TSource, TResult>(this IEnumerable<TSource> source, Func<TSource, int, TResult> selector)
								var pars = methodCall.Method.GetParameters();
								if (pars.Length != 2)
								{
									throw new NotSupportedException("The `Enumerable.Contains` method must have 2 parameters.");
								}
								
								if (methodCall.Arguments[0].IsFieldExpression())
								{
									var value = GetFieldExpressionValue(methodCall.Arguments[0]);
									writer.Write($"{value ?? "[]"}.includes");
								}
								else 
								{
									writer.Write("(");
									context.Visitor.Visit(methodCall.Arguments[0]);
									writer.Write("||[]).includes");
								}
							}

							writer.Write('(');

							// separator
							using (writer.Operation(0))
								if (methodCall.Arguments[1].IsFieldExpression())
								{
									var value = GetFieldExpressionValue(methodCall.Arguments[1]);
									writer.Write(value ?? "null");
								}
								else
								{
									context.Visitor.Visit(methodCall.Arguments[1]);
								}

							writer.Write(')');
						}

						return;
					}
			}
		}
		else if (methodCall.Method.DeclaringType == typeof(Array))
		{
			switch (methodCall.Method.Name)
			{
				case "IndexOf":
					{
						context.PreventDefault();
						var writer = context.GetWriter();
						using (writer.Operation(JavascriptOperationTypes.Call))
						{
							using (writer.Operation(JavascriptOperationTypes.IndexerProperty))
							{
								// public static IEnumerable<TResult> Select<TSource, TResult>(this IEnumerable<TSource> source, Func<TSource, TResult> selector)
								// public static IEnumerable<TResult> Select<TSource, TResult>(this IEnumerable<TSource> source, Func<TSource, int, TResult> selector)
								var pars = methodCall.Method.GetParameters();
								if (pars.Length != 2)
								{
									throw new NotSupportedException("The `Enumerable.Contains` method must have 2 parameters.");
								}

								if (methodCall.Arguments[0].IsFieldExpression())
								{
									var value = GetFieldExpressionValue(methodCall.Arguments[0]);
									writer.Write($"{value ?? "[]"}.indexOf");
								}
								else
								{
									writer.Write("(");
									context.Visitor.Visit(methodCall.Arguments[0]);
									writer.Write("||[]).indexOf");
								}
							}

							writer.Write('(');

							// separator
							using (writer.Operation(0))
								if (methodCall.Arguments[1].IsFieldExpression())
								{
									var value = GetFieldExpressionValue(methodCall.Arguments[1]);
									writer.Write(value ?? "null");
								}
								else
								{
									context.Visitor.Visit(methodCall.Arguments[1]);
								}

							writer.Write(')');
						}

						return;
					}
			}
		}
		else if ((methodCall.Method.DeclaringType?.IsGenericType ?? false) && methodCall.Method.DeclaringType.GetGenericTypeDefinition() == typeof(List<>))
		{
			switch (methodCall.Method.Name)
			{
				case "Contains":
				{
					context.PreventDefault();
					var writer = context.GetWriter();
					using (writer.Operation(JavascriptOperationTypes.Call))
					{
						using (writer.Operation(JavascriptOperationTypes.IndexerProperty))
						{
							var pars = methodCall.Method.GetParameters();
							if (pars.Length != 1)
							{
								throw new NotSupportedException("The `List.Contains` method must have 1 parameters.");
							}

							writer.Write("(");
								
							context.Visitor.Visit(methodCall.Object);

							writer.Write("||[]).includes");
						}

						writer.Write('(');

						// separator
						using (writer.Operation(0))
							if (methodCall.Arguments[0].IsFieldExpression())
							{
								var value = GetFieldExpressionValue(methodCall.Arguments[0]);
								writer.Write(value ?? "null");
							}
							else
							{
								context.Visitor.Visit(methodCall.Arguments[0]);
							}

						writer.Write(')');
					}

					return;
				}
			}
		}
	}

	private static object GetFieldExpressionValue(Expression member)
	{
		var value = Expression.Lambda(member).Compile().DynamicInvoke();
		var valueType = value?.GetType();
		
		return GetExpressionValue(valueType, value);
	}
	
	private static object GetExpressionValue(Type valueType, object value)
	{
		if (valueType.IsArrayOf<string>())
		{
			return $"['{string.Join("','", (string[])value)}']";
		}

		if (valueType.IsArrayOf<DateTime>())
		{
			return $"['{string.Join("','", ((DateTime[])value).Select(v => v.ToString("O")))}']";
		}

		if (valueType.IsArrayOf<bool>())
		{
			return $"[{string.Join(",", ((bool[])value).Select(v => v ? "true" : "false"))}]";
		}

		switch (value)
		{
			case float[] val:
				return $"[{string.Join(',', val)}]";
			case decimal[] val:
				return $"[{string.Join(',', val)}]";
			case double[] val:
				return $"[{string.Join(',', val)}]";
			case int[] val:
				return $"[{string.Join(',', val)}]";
			case long[] val:
				return $"[{string.Join(',', val)}]";
		}
		
		if (value is null || !(valueType.IsValueType || valueType == typeof(string)))
		{
			return value;
		}

		return valueType == typeof(string)
			? $"'{value}'"
			: valueType == typeof(bool)
				? (bool) value ? "true" : "false"
			: valueType == typeof(DateTime)
				? $"'{value:O}'"
				: value;
	}
}