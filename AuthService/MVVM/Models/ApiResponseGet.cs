using System;
using System.Collections.Generic;
using System.Net;
using System.Text.Json.Serialization;

namespace AuthService.Services
{
    public class ApiResponseGet
    {
        [JsonPropertyName("code")]
        public int Code { get; set; }

        [JsonPropertyName("success")]
        public bool Success { get; set; }

        [JsonPropertyName("message")]
        public string Message { get; set; }

        [JsonPropertyName("time")]
        public DateTime time { get; set; }

        [JsonPropertyName("payload")]
        public PayloadData Payload { get; set; }
    }

    public class PayloadData
    {
        [JsonPropertyName("subscription")]
        public Subscription Subscription { get; set; }

        [JsonPropertyName("redemptions")]
        public List<Redemption> Redemptions { get; set; }
        [JsonPropertyName("addon")]
        public addon addon { get; set; }
        [JsonPropertyName("count")]
        public int Count { get; set; }
    }

    public class addon
    {
        [JsonPropertyName("guid")]
        public string guid { get; set; }
        [JsonPropertyName("Name")]
        public string Name { get; set; }
    }

    public class Subscription
    {
        [JsonPropertyName("id")]
        public int Id { get; set; }

        [JsonPropertyName("user_id")]
        public int UserId { get; set; }

        [JsonPropertyName("addon_id")]
        public int AddonId { get; set; }

        [JsonPropertyName("voucher_id")]
        public int? VoucherId { get; set; }

        [JsonPropertyName("start_date")]
        [JsonConverter(typeof(DateTimeConverter))]
        public DateTime StartDate { get; set; }

        [JsonPropertyName("end_date")]
        [JsonConverter(typeof(DateTimeConverter))]
        public DateTime EndDate { get; set; }

        [JsonPropertyName("frequency")]
        public string Frequency { get; set; }

        [JsonPropertyName("price")]
        public string Price { get; set; }

        [JsonPropertyName("status")]
        public string Status { get; set; }

        [JsonPropertyName("paymob_order_id")]
        public string PaymobOrderId { get; set; }

        [JsonPropertyName("code")]
        public string Code { get; set; }

        [JsonPropertyName("created_at")]
        public string CreatedAt { get; set; }

        [JsonPropertyName("updated_at")]
        public string UpdatedAt { get; set; }

        [JsonPropertyName("is_trial")]
        public bool IsTrial { get; set; }
    }

    public class Redemption
    {
        [JsonPropertyName("id")]
        public int Id { get; set; }

        [JsonPropertyName("subscription_id")]
        public int SubscriptionId { get; set; }

        [JsonPropertyName("data")]
        public List<string> Data { get; set; }

        [JsonPropertyName("ip_address")]
        public IPAddress IpAddress { get; set; }

        [JsonPropertyName("created_at")]
        public DateTime CreatedAt { get; set; }

        [JsonPropertyName("updated_at")]
        public DateTime UpdatedAt { get; set; }
    }
}
