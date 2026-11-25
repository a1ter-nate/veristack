export interface JobFlags {
  isRunning: boolean;
  isStopped: boolean;
  hasFailed: boolean;
}

export interface PaymentBag {
  status: "pending" | "captured" | "failed";
  authCode?: string;
  failureReason?: string;
}

export function describePayment(payment: PaymentBag): string {
  switch (payment.status) {
    case "pending":
      return "Waiting";
    case "captured":
      return "Done";
  }
  return "Unknown";
}
