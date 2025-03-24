using System;
using System.Collections.Generic;

namespace SapphTools.Logging {
    internal class LogChunk {
        public DateTime Timestamp { get; set; }
        public List<string> Lines { get; } = new List<string>();
    }
}
