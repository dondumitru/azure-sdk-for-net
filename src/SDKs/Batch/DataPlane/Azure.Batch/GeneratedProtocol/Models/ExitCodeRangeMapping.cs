// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for
// license information.
//
// Code generated by Microsoft (R) AutoRest Code Generator.
// Changes may cause incorrect behavior and will be lost if the code is
// regenerated.

namespace Microsoft.Azure.Batch.Protocol.Models
{
    using System.Linq;

    /// <summary>
    /// A range of exit codes and how the Batch service should respond to exit
    /// codes within that range.
    /// </summary>
    public partial class ExitCodeRangeMapping
    {
        /// <summary>
        /// Initializes a new instance of the ExitCodeRangeMapping class.
        /// </summary>
        public ExitCodeRangeMapping() { }

        /// <summary>
        /// Initializes a new instance of the ExitCodeRangeMapping class.
        /// </summary>
        /// <param name="start">The first exit code in the range.</param>
        /// <param name="end">The last exit code in the range.</param>
        /// <param name="exitOptions">How the Batch service should respond if
        /// the task exits with an exit code in the range start to end
        /// (inclusive).</param>
        public ExitCodeRangeMapping(int start, int end, ExitOptions exitOptions)
        {
            Start = start;
            End = end;
            ExitOptions = exitOptions;
        }

        /// <summary>
        /// Gets or sets the first exit code in the range.
        /// </summary>
        [Newtonsoft.Json.JsonProperty(PropertyName = "start")]
        public int Start { get; set; }

        /// <summary>
        /// Gets or sets the last exit code in the range.
        /// </summary>
        [Newtonsoft.Json.JsonProperty(PropertyName = "end")]
        public int End { get; set; }

        /// <summary>
        /// Gets or sets how the Batch service should respond if the task exits
        /// with an exit code in the range start to end (inclusive).
        /// </summary>
        [Newtonsoft.Json.JsonProperty(PropertyName = "exitOptions")]
        public ExitOptions ExitOptions { get; set; }

        /// <summary>
        /// Validate the object.
        /// </summary>
        /// <exception cref="Microsoft.Rest.ValidationException">
        /// Thrown if validation fails
        /// </exception>
        public virtual void Validate()
        {
            if (ExitOptions == null)
            {
                throw new Microsoft.Rest.ValidationException(Microsoft.Rest.ValidationRules.CannotBeNull, "ExitOptions");
            }
        }
    }
}