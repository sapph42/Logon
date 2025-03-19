using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Policy;
using System.Text;
using System.Threading.Tasks;

namespace System.Diagnostics.CodeAnalysis;

[AttributeUsage(AttributeTargets.Method | AttributeTargets.Property, Inherited = false, AllowMultiple = true)]
internal sealed class MemberNotNullAttribute :Attribute {
    public MemberNotNullAttribute(string member) => Members = new[] { member };
    public MemberNotNullAttribute(params string[] members) => Members = members;
    public string[] Members { get; }
}
