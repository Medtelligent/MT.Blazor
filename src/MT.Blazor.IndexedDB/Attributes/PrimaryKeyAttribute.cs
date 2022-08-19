using System;

namespace MT.Blazor.IndexedDB.Attributes;

[AttributeUsage(AttributeTargets.Property)]
public sealed class PrimaryKeyAttribute : Attribute
{
    public bool AutoIncrement { get; set; }
}