﻿// Author: Ryan Cobb (@cobbr_io)
// Project: SharpSploit (https://github.com/cobbr/SharpSploit)
// License: BSD 3-Clause

using System;
using System.Text;
using System.Linq;
using System.Collections.Generic;
using System.Collections;

namespace SharpSploit.Generic
{
    /// <summary>
    /// GenericObjectResult for listing objects whose type is unknown at compile time.
    /// </summary>
    public sealed class GenericObjectResult : SharpSploitResult
    {
        public object Result { get; }
        protected internal override IList<SharpSploitResultProperty> ResultProperties
        {
            get
            {
                return new List<SharpSploitResultProperty>
                    {
                        new SharpSploitResultProperty
                        {
                            Name = this.Result.GetType().Name,
                            Value = this.Result
                        }
                    };
            }
        }

        public GenericObjectResult(object Result)
        {
            this.Result = Result;
        }
    }

    /// <summary>
    /// SharpSploitResultList extends the IList interface for SharpSploitResults to easily
    /// format a list of results from various SharpSploit functions.
    /// </summary>
    /// <typeparam name="T"></typeparam>
    public class SharpSploitResultList<T> : IList<T> where T : SharpSploitResult
    {
        private List<T> Results { get; } = new List<T>();

        public int Count => Results.Count;
        public bool IsReadOnly => ((IList<T>)Results).IsReadOnly;


        private const int PROPERTY_SPACE = 3;

        /// <summary>
        /// Formats a SharpSploitResultList to a string similar to PowerShell's Format-List function.
        /// </summary>
        /// <returns>string</returns>
        public string FormatList()
        {
            return this.ToString();
        }

        private string FormatTable()
        {
            return "";
        }
        
        /// <summary>
        /// Formats a SharpSploitResultList as a string. Overrides ToString() for convenience.
        /// </summary>
        /// <returns>string</returns>
        public override string ToString()
        {
            if (this.Results.Count > 0)
            {
                StringBuilder builder1 = new StringBuilder();
                StringBuilder builder2 = new StringBuilder();
                for (int i = 0; i < this.Results[0].ResultProperties.Count; i++)
                {
                    builder1.Append(this.Results[0].ResultProperties[i].Name);
                    builder2.Append(new String('-', this.Results[0].ResultProperties[i].Name.Length));
                    if (i != this.Results[0].ResultProperties.Count-1)
                    {
                        builder1.Append(new String(' ', PROPERTY_SPACE));
                        builder2.Append(new String(' ', PROPERTY_SPACE));
                    }
                }
                builder1.AppendLine();
                builder1.AppendLine(builder2.ToString());
                foreach (SharpSploitResult result in this.Results)
                {
                    for (int i = 0; i < result.ResultProperties.Count; i++)
                    {
                        SharpSploitResultProperty property = result.ResultProperties[i];
                        string ValueString = property.Value.ToString();
                        builder1.Append(ValueString);
                        if (i != result.ResultProperties.Count-1)
                        {
                            builder1.Append(new String(' ', Math.Max(1, property.Name.Length + PROPERTY_SPACE - ValueString.Length)));
                        }
                    }
                    builder1.AppendLine();
                }
                return builder1.ToString();
            }
            return "";
        }

        public T this[int index] { get => Results[index]; set => Results[index] = value; }

        public IEnumerator<T> GetEnumerator()
        {
            return Results.Cast<T>().GetEnumerator();
        }

        IEnumerator IEnumerable.GetEnumerator()
        {
            return Results.Cast<T>().GetEnumerator();
        }

        public int IndexOf(T item)
        {
            return Results.IndexOf(item);
        }

        public void Add(T t)
        {
            Results.Add(t);
        }

        public void AddRange(IEnumerable<T> range)
        {
            Results.AddRange(range);
        }

        public void Insert(int index, T item)
        {
            Results.Insert(index, item);
        }

        public void RemoveAt(int index)
        {
            Results.RemoveAt(index);
        }

        public void Clear()
        {
            Results.Clear();
        }

        public bool Contains(T item)
        {
            return Results.Contains(item);
        }

        public void CopyTo(T[] array, int arrayIndex)
        {
            Results.CopyTo(array, arrayIndex);
        }

        public bool Remove(T item)
        {
            return Results.Remove(item);
        }
    }

    /// <summary>
    /// Abstract class that represents a result from a SharpSploit function.
    /// </summary>
    public abstract class SharpSploitResult
    {
        protected internal abstract IList<SharpSploitResultProperty> ResultProperties { get; }
    }

    /// <summary>
    /// SharpSploitResultProperty represents a property that is a member of a SharpSploitResult's ResultProperties.
    /// </summary>
    public class SharpSploitResultProperty
    {
        public string Name { get; set; }
        public object Value { get; set; }
    }
}
