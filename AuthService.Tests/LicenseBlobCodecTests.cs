using System;
using System.IO;
using System.Text;
using AuthService.Services.Licensing;
using Xunit;

public class LicenseBlobCodecTests
{
    [Fact]
    public void RoundTrips_AllFields()
    {
        var original = new StoredLicense
        {
            Token = "eyJhbGciOiJFUzI1NiJ9.payload.sig",
            MaxDateSeen = DateTimeOffset.FromUnixTimeSeconds(1_750_000_000),
            IsRevoked = true
        };

        var back = LicenseBlobCodec.Decode(LicenseBlobCodec.Encode(original));

        Assert.NotNull(back);
        Assert.Equal(original.Token, back.Token);
        Assert.Equal(original.MaxDateSeen.ToUnixTimeSeconds(), back.MaxDateSeen.ToUnixTimeSeconds());
        Assert.True(back.IsRevoked);
    }

    [Fact]
    public void Blob_IsOpaque_NotReadableJson()
    {
        var blob = LicenseBlobCodec.Encode(new StoredLicense
        {
            Token = "abc.def.ghi",
            MaxDateSeen = DateTimeOffset.FromUnixTimeSeconds(1_750_000_000)
        });

        var asText = Encoding.UTF8.GetString(blob);
        Assert.DoesNotContain("MaxDateSeen", asText);
        Assert.DoesNotContain("IsRevoked", asText);
        Assert.DoesNotContain("Token", asText);
        Assert.DoesNotContain("abc.def.ghi", asText);
        // Not JSON: the first byte is the "FOL1" magic, not '{'.
        Assert.NotEqual((byte)'{', blob[0]);
    }

    [Fact]
    public void Decode_RejectsAnyEditedByte()
    {
        var blob = LicenseBlobCodec.Encode(new StoredLicense
        {
            Token = "abc.def.ghi",
            MaxDateSeen = DateTimeOffset.FromUnixTimeSeconds(1_750_000_000)
        });

        // Flip a byte in the encrypted middle of the record. The MAC must reject it.
        var tampered = (byte[])blob.Clone();
        int mid = blob.Length / 2;
        tampered[mid] ^= 0xFF;

        Assert.Null(LicenseBlobCodec.Decode(tampered));
    }

    [Fact]
    public void Store_Read_ReturnsNull_WhenFileHandEdited()
    {
        var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ".json");
        var store = new LicenseStore(path);
        store.Write(new StoredLicense
        {
            Token = "abc.def.ghi",
            MaxDateSeen = DateTimeOffset.FromUnixTimeSeconds(1_750_000_000)
        });

        var bytes = File.ReadAllBytes(path);
        bytes[bytes.Length / 2] ^= 0x01; // one-bit edit
        File.WriteAllBytes(path, bytes);

        Assert.Null(store.Read());

        File.Delete(path);
    }

    [Fact]
    public void Decode_ReturnsNull_OnGarbage()
    {
        Assert.Null(LicenseBlobCodec.Decode(null));
        Assert.Null(LicenseBlobCodec.Decode(Array.Empty<byte>()));
        Assert.Null(LicenseBlobCodec.Decode(Encoding.UTF8.GetBytes("{\"Token\":\"x\"}")));
    }
}
