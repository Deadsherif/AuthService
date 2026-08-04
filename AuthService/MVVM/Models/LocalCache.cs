using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace AuthService8.MVVM.Models
{
    public sealed class LocalCacheFile
    {

        [JsonPropertyName("Entries")]
        public Dictionary<string, LocalCacheEntry> Entries { get; set; } = new Dictionary<string, LocalCacheEntry>();
    }

    public sealed class LocalCacheEntry  
    {
        [JsonPropertyName("AddinName")]
        public string AddinName { get; set; }
        [JsonPropertyName("Mac")]
        public string Mac { get; set; }
        [JsonPropertyName("TimeStamp")]
        public DateTime TimeStamp { get; set; }
        [JsonPropertyName("code")]
        public string code { get; set; }
    }

}
