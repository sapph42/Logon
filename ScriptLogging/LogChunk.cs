using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SapphTools.Logging {
    internal class LogChunk {
        public DateTime Timestamp { get; set; }
        public List<string> Lines { get; } = new List<string>();
    }
}
