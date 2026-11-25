namespace Veristack.Examples.Caught;

public sealed class JobFlags
{
    public bool IsRunning { get; set; }
    public bool IsStopped { get; set; }
    public bool HasFailed { get; set; }
}

public sealed class PaymentBag
{
    public string Status { get; set; } = "pending";
    public string? AuthCode { get; set; }
    public string? FailureReason { get; set; }

    public string Label() => Status switch
    {
        "pending" => "Waiting",
        "captured" => "Done",
        _ => "Unknown"
    };
}
