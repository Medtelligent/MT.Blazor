using System;

namespace MT.Blazor.IndexedDB.Attributes;

[AttributeUsage(AttributeTargets.Property)]
public sealed class IndexAttribute : Attribute
{
    public IndexAttribute(string name)
    {
        Name = name;
    }
        
    public string Name { get; set; }
        
    public bool Unique { get; set; }
    
    public bool MultiEntry { get; set; }

    public bool AutoIncrement { get; set; }
}