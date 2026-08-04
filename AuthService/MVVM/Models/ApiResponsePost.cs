using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.Json.Serialization;   
using System.Threading.Tasks;

namespace AuthService.MVVM.Models
{
    public class ApiResponsePost
    {
        [JsonPropertyName("code")]
        public int Code { get; set; }

        [JsonPropertyName("success")]
        public bool Success { get; set; }

        [JsonPropertyName("message")]
        public string Message { get; set; }

        [JsonPropertyName("payload")]
        public object Payload { get; set; }
        [JsonPropertyName("time")]
        public DateTime time { get; set; }
    }
}
