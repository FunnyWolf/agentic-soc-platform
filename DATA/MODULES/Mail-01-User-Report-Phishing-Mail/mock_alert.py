from PLUGINS.Redis.redis_stream_api import RedisStreamAPI

mail_records = [
    # ----------------------------------------------------
    # A. 合法邮件记录 (1-10) - malicious: False
    # ----------------------------------------------------
    {
        "headers": {
            "From": "\"Amazon Shipping\" <ship-update@amazon.com>",
            "To": "\"Valued Customer\" <user@example.com>",
            "Subject": "[Order #872934] Your Amazon order has shipped!",
            "Date": "Wed, 5 Nov 2025 16:21:05 +0800",
            "Return-Path": "<notifications@bounce.amazon.com>",
            "Authentication-Results": "mx.example.com; spf=pass smtp.mail=ship-update@amazon.com; dkim=pass header.d=amazon.com; dmarc=pass (p=QUARANTINE sp=QUARANTINE) header.from=amazon.com",
        },
        "body": {
            "plain_text": "Hello Valued Customer,\n\nGood news! Your Amazon order #872934 has shipped and is scheduled to arrive on 2025-11-08.\n\nTracking Number: 456789123456\nCarrier: FedEx\n\nTrack your package here:\nhttps://www.amazon.com/gp/your-account/order-details/tracking-link?orderId=872934\n\nThank you for shopping with us.\n\nAmazon Customer Service",
            "html": "<html><body><p>Hello Valued Customer,</p><p>Good news! Your <b>Amazon order #872934</b> has shipped and is scheduled to arrive on <b>2025-11-08</b>.</p><p>Tracking Number: 456789123456</p><p>Carrier: FedEx</p><p>Track your package here:<br><a href='https://www.amazon.com/gp/your-account/order-details/tracking-link?orderId=872934'>Track Your Package</a></p><p>Thank you for shopping with us.</p><p>Amazon Customer Service</p></body></html>"
        },
        "attachments": [],

    },
    {
        "headers": {
            "From": "\"Google Security\" <no-reply@accounts.google.com>",
            "To": "\"Valued Customer\" <user@example.com>",
            "Subject": "Google Security Alert: New sign-in from Chrome on Windows",
            "Date": "Wed, 5 Nov 2025 10:05:00 +0000",
            "Return-Path": "<bounce@accounts.google.com>",
            "Authentication-Results": "mx.example.com; spf=pass smtp.mail=no-reply@accounts.google.com; dkim=pass header.d=google.com; dmarc=pass (p=REJECT sp=REJECT) header.from=google.com",
        },
        "body": {
            "plain_text": "Someone just signed in to your Google Account user@example.com from Chrome on Windows. If this was you, you can safely ignore this email.\n\nIf you don't recognize this activity, review your account security immediately:\n\nhttps://myaccount.google.com/notifications/chgsec/review-activity?id=1234567890\n\nGoogle Accounts Team",
            "html": "<html><body><p>Someone just signed in to your Google Account user@example.com from Chrome on Windows. If this was you, you can safely ignore this email.</p><p>If you don't recognize this activity, review your account security immediately:<br><a href='https://myaccount.google.com/notifications/chgsec/review-activity?id=1234567890'>Review Activity</a></p><p>Google Accounts Team</p></body></html>"
        },
        "attachments": [],

    },
    {
        "headers": {
            "From": "\"Medium Digest\" <noreply@medium.com>",
            "To": "\"Valued Customer\" <user@example.com>",
            "Subject": "Weekly Digest: Top Articles in Machine Learning",
            "Date": "Mon, 3 Nov 2025 08:00:00 -0500",
            "Return-Path": "<bounce@medium.com>",
            "Authentication-Results": "mx.example.com; spf=pass smtp.mail=noreply@medium.com; dkim=pass header.d=medium.com",
        },
        "body": {
            "plain_text": "Your Weekly Dose of Knowledge.\n\nFeatured Article: The Rise of LLMs and Their Impact on Software Engineering\n\nRead Now: https://medium.com/p/llms-impact-on-se/2839458\n\nSee all featured stories on Medium:\nhttps://medium.com/home/digest",
            "html": "<html><body><p>Your Weekly Dose of Knowledge.</p><p><b>Featured Article:</b> The Rise of LLMs and Their Impact on Software Engineering</p><p><a href='https://medium.com/p/llms-impact-on-se/2839458'>Read Now</a></p><p>See all featured stories on Medium:<br><a href='https://medium.com/home/digest'>Visit Medium</a></p></body></html>"
        },
        "attachments": [],

    },
    {
        "headers": {
            "From": "\"Freelancer Inc. Billing\" <billing@freelancerinc.co>",
            "To": "\"Valued Customer\" <user@example.com>",
            "Subject": "Invoice 2025-11-05 from Freelancer Inc.",
            "Date": "Wed, 5 Nov 2025 15:45:00 +0800",
            "Return-Path": "<postmaster@freelancerinc.co>",
            "Authentication-Results": "mx.example.com; spf=pass smtp.mail=billing@freelancerinc.co; dkim=pass header.d=freelancerinc.co",
        },
        "body": {
            "plain_text": "Dear Valued Customer,\n\nPlease find attached the invoice for services rendered in October 2025. Total amount due is $1,250.00.\n\nDue Date: 2025-11-20\n\nView invoice details online:\nhttps://billing.freelancerinc.co/invoice/view/2025-11-05-123\n\nThank you for your business.",
            "html": "<html><body><p>Dear Valued Customer,</p><p>Please find attached the invoice for services rendered in October 2025. Total amount due is <b>$1,250.00</b>.</p><p>Due Date: 2025-11-20</p><p>View invoice details online:<br><a href='https://billing.freelancerinc.co/invoice/view/2025-11-05-123'>View Invoice</a></p></body></html>"
        },
        "attachments": [
            {
                "filename": "Invoice_2025-11-05.pdf",
                "filepath": "attachments/Invoice_2025-11-05.pdf",
                "content_type": "application/pdf"
            }
        ],

    },
    {
        "headers": {
            "From": "\"Apple\" <appleid@id.apple.com>",
            "To": "\"Valued Customer\" <user@example.com>",
            "Subject": "Your Password Reset Request - Apple ID",
            "Date": "Wed, 5 Nov 2025 14:10:30 +0800",
            "Return-Path": "<noreply@id.apple.com>",
            "Authentication-Results": "mx.example.com; spf=pass smtp.mail=appleid@id.apple.com; dkim=pass header.d=apple.com",
        },
        "body": {
            "plain_text": "Dear user@example.com,\n\nYou requested a password reset for your Apple ID. Click the link below to continue the process.\n\nhttps://iforgot.apple.com/password/verify/session/123xyz456\n\nIf you did NOT request this password reset, you can safely ignore this email. Your password will remain the same.\n\nApple Support",
            "html": "<html><body><p>Dear user@example.com,</p><p>You requested a password reset for your Apple ID. Click the link below to continue the process.</p><p><a href='https://iforgot.apple.com/password/verify/session/123xyz456'>Reset Your Password</a></p><p>If you did <b>NOT</b> request this password reset, you can safely ignore this email. Your password will remain the same.</p><p>Apple Support</p></body></html>"
        },
        "attachments": [],

    },
    {
        "headers": {
            "From": "\"Cloud Services Team\" <notifications@cloudservice.com>",
            "To": "\"Valued Customer\" <user@example.com>",
            "Subject": "Upcoming Scheduled Maintenance for Cloud Services",
            "Date": "Mon, 3 Nov 2025 11:00:00 -0800",
            "Return-Path": "<noreply@cloudservice.com>",
            "Authentication-Results": "mx.example.com; spf=pass smtp.mail=notifications@cloudservice.com; dkim=pass header.d=cloudservice.com",
        },
        "body": {
            "plain_text": "Dear Customers,\n\nWe will be performing scheduled maintenance on our API gateway during the following window:\n\nStart: Saturday, November 8, 2025, 01:00 AM UTC\nEnd: Saturday, November 8, 2025, 03:00 AM UTC\n\nExpected Impact: Minor delays in API responses.\n\nThank you for your understanding.\n\nCloud Services Team",
            "html": "<html><body><p>Dear Customers,</p><p>We will be performing scheduled maintenance on our API gateway during the following window:</p><ul><li><b>Start:</b> Saturday, November 8, 2025, 01:00 AM UTC</li><li><b>End:</b> Saturday, November 8, 2025, 03:00 AM UTC</li></ul><p>Expected Impact: Minor delays in API responses.</p><p>Thank you for your understanding.</p><p>Cloud Services Team</p></body></html>"
        },
        "attachments": [],

    },
    {
        "headers": {
            "From": "\"GitHub\" <noreply@github.com>",
            "To": "\"Valued Customer\" <user@example.com>",
            "Subject": "Welcome to GitHub! Get Started with Your First Repository",
            "Date": "Tue, 4 Nov 2025 09:30:00 +0000",
            "Return-Path": "<postmaster@github.com>",
            "Authentication-Results": "mx.example.com; spf=pass smtp.mail=noreply@github.com; dkim=pass header.d=github.com",
        },
        "body": {
            "plain_text": "Hi user,\n\nWelcome to the world's leading software development platform. We're excited to have you!\n\nHere are your first steps:\n1. Create a Repository: https://github.com/new\n2. Explore Documentation: https://docs.github.com\n\nHappy coding!\n\nThe GitHub Team",
            "html": "<html><body><p>Hi user,</p><p>Welcome to the world's leading software development platform. We're excited to have you!</p><p>Here are your first steps:</p><ol><li><a href='https://github.com/new'>Create a Repository</a></li><li><a href='https://docs.github.com'>Explore Documentation</a></li></ol><p>Happy coding!</p><p>The GitHub Team</p></body></html>"
        },
        "attachments": [],

    },
    {
        "headers": {
            "From": "\"Emirates Airlines\" <booking@emirates.com>",
            "To": "\"Valued Customer\" <user@example.com>",
            "Subject": "Your Flight Confirmation: Booking Ref ABCD12",
            "Date": "Tue, 4 Nov 2025 18:00:00 +0400",
            "Return-Path": "<noreply@emirates.com>",
            "Authentication-Results": "mx.example.com; spf=pass smtp.mail=booking@emirates.com; dkim=pass header.d=emirates.com",
        },
        "body": {
            "plain_text": "Dear Mr./Ms. Customer,\n\nYour flight from Dubai (DXB) to Singapore (SIN) on November 20, 2025 has been successfully booked.\n\nBooking Reference: ABCD12\nFlight: EK 354\n\nView and manage your booking:\nhttps://www.emirates.com/manage-booking?ref=ABCD12\n\nWe look forward to welcoming you onboard.",
            "html": "<html><body><p>Dear Mr./Ms. Customer,</p><p>Your flight from Dubai (DXB) to Singapore (SIN) on November 20, 2025 has been successfully booked.</p><p>Booking Reference: <b>ABCD12</b></p><p>Flight: <b>EK 354</b></p><p>View and manage your booking:<br><a href='https://www.emirates.com/manage-booking?ref=ABCD12'>Manage Booking</a></p><p>We look forward to welcoming you onboard.</p></body></html>"
        },
        "attachments": [
            {
                "filename": "E-Ticket_ABCD12.ics",
                "filepath": "attachments/E-Ticket_ABCD12.ics",
                "content_type": "text/calendar"
            }
        ],

    },
    {
        "headers": {
            "From": "\"Microsoft 365 News\" <newsletter@microsoft.com>",
            "To": "\"Valued Customer\" <user@example.com>",
            "Subject": "Quarterly Newsletter: New Features in Microsoft 365",
            "Date": "Mon, 3 Nov 2025 13:00:00 -0500",
            "Return-Path": "<newsletter-bounce@microsoft.com>",
            "Authentication-Results": "mx.example.com; spf=pass smtp.mail=newsletter@microsoft.com; dkim=pass header.d=microsoft.com",
        },
        "body": {
            "plain_text": "Stay productive with the latest updates from Microsoft 365.\n\nFeature Spotlight: Real-time co-authoring in Excel is now generally available.\n\nRead the full update here: https://support.microsoft.com/en-us/office/whats-new-in-microsoft-365\n\nUnsubscribe link: https://preferences.microsoft.com/unsubscribe/12345",
            "html": "<html><body><p>Stay productive with the latest updates from Microsoft 365.</p><p>Feature Spotlight: <b>Real-time co-authoring in Excel</b> is now generally available.</p><p><a href='https://support.microsoft.com/en-us/office/whats-new-in-microsoft-365'>Read the full update here</a></p><p>Unsubscribe link: <a href='https://preferences.microsoft.com/unsubscribe/12345'>Unsubscribe</a></p></body></html>"
        },
        "attachments": [],

    },
    {
        "headers": {
            "From": "\"Spotify Billing\" <billing@spotify.com>",
            "To": "\"Valued Customer\" <user@example.com>",
            "Subject": "Payment Confirmation: $19.99 successfully processed by Spotify",
            "Date": "Wed, 5 Nov 2025 09:15:00 +0000",
            "Return-Path": "<noreply@spotify.com>",
            "Authentication-Results": "mx.example.com; spf=pass smtp.mail=billing@spotify.com; dkim=pass header.d=spotify.com",
        },
        "body": {
            "plain_text": "Hi,\n\nYour monthly payment of $19.99 for your Spotify Family plan has been successfully processed.\n\nNext billing date: December 5, 2025\n\nManage your subscription or view receipts:\nhttps://www.spotify.com/account/subscription/receipts\n\nThanks for being a subscriber!",
            "html": "<html><body><p>Hi,</p><p>Your monthly payment of <b>$19.99</b> for your Spotify Family plan has been successfully processed.</p><p>Next billing date: December 5, 2025</p><p>Manage your subscription or view receipts:<br><a href='https://www.spotify.com/account/subscription/receipts'>Go to Account</a></p><p>Thanks for being a subscriber!</p></body></html>"
        },
        "attachments": [],

    },
    # ----------------------------------------------------
    # B. 恶意邮件记录 (11-20) - malicious: True (抽象化/夸大特征)
    # ----------------------------------------------------
    {
        "headers": {
            "From": "\"Secure Bank Alert\" <alert-no-reply@secure-finance-portal.xyz>",
            "To": "\"Customer Account\" <user@example.com>",
            "Subject": "URGENT Action Required: Your Transaction has been Blocked",
            "Date": "Wed, 5 Nov 2025 16:22:15 +0800",
            "Return-Path": "<bounce-scam@phish-delivery-2.net>",
            "Authentication-Results": "mx.example.com; spf=fail smtp.mail=alert-no-reply@secure-finance-portal.xyz; dkim=fail header.d=secure-finance-portal.xyz; dmarc=fail (p=REJECT sp=REJECT) header.from=secure-finance-portal.xyz",
        },
        "body": {
            "plain_text": "Dear Account Holder,\n\nOur system has detected a high-risk, unauthorized transaction attempt from an unknown location.\n\nTo prevent further fraud, we have temporarily frozen your funds and suspended all activity.\n\nClick the link below IMMEDIATELY to verify your identity and confirm the transaction details:\n\nhttp://verification-required-999.com/unlock-account?id=user@example.com\n\nFailure to comply within 3 hours will result in a permanent block of your account.\n\nSecurity Department",
            "html": "<html><body><p>Dear Account Holder,</p><p>Our system has detected a <b>high-risk, unauthorized transaction</b> attempt from an unknown location.</p><p>To prevent further fraud, we have temporarily frozen your funds and suspended all activity.</p><p>Click the link below <b>IMMEDIATELY</b> to verify your identity and confirm the transaction details:</p><p><a href='http://verification-required-999.com/unlock-account?id=user@example.com'>Verify Account Now (Secure Link)</a></p><p>Failure to comply within 3 hours will result in a permanent block of your account.</p></body></html>"
        },
        "attachments": [
            {
                "filename": "Transaction_Details_Report.zip",
                "filepath": "attachments/Transaction_Details_Report.zip",
                "content_type": "application/zip"
            }
        ],

    },
    {
        "headers": {
            "From": "\"Admin Support\" <admin-notice@login-verify-host.net>",
            "To": "\"Customer Account\" <user@example.com>",
            "Subject": "[SECURE-NOTICE] Verify Your Email or Account Deletion",
            "Date": "Thu, 6 Nov 2025 09:00:00 +0800",
            "Return-Path": "<error-bounce@phish-delivery-3.net>",
            "Authentication-Results": "mx.example.com; spf=fail smtp.mail=admin-notice@login-verify-host.net; dkim=fail header.d=login-verify-host.net",
        },
        "body": {
            "plain_text": "Warning: Our records indicate your email address has not been verified in the last 6 months. To avoid immediate account deletion and loss of all data, you must click the link below.\n\nVerification Deadline: 12 hours.\n\nVerify Your Account Now:\nhttp://update-login-required.com/verify/login.php?user=example",
            "html": "<html><body><p>Warning: Our records indicate your email address has not been verified in the last 6 months. To avoid <b>immediate account deletion</b> and loss of all data, you must click the link below.</p><p>Verification Deadline: 12 hours.</p><p><a href='http://update-login-required.com/verify/login.php?user=example'>Verify Your Account Now</a></p></body></html>"
        },
        "attachments": [],

    },
    {
        "headers": {
            "From": "\"IRS Refund Dept\" <noreply@tax-refund-gov.com>",
            "To": "\"Tax Filer\" <user@example.com>",
            "Subject": "TAX Refund Notification: Click to Receive Your Overpayment",
            "Date": "Wed, 5 Nov 2025 15:30:00 +0800",
            "Return-Path": "<bounce@phish-delivery-4.net>",
            "Authentication-Results": "mx.example.com; spf=fail smtp.mail=noreply@tax-refund-gov.com; dkim=fail header.d=tax-refund-gov.com",
        },
        "body": {
            "plain_text": "Dear Tax Filer,\n\nWe have determined that you are eligible for a tax overpayment refund of $450.00.\n\nTo claim your refund, please fill out the secure form here:\nhttp://tax-claim-online.net/form/get-refund\n\nNote: This offer expires in 48 hours.",
            "html": "<html><body><p>Dear Tax Filer,</p><p>We have determined that you are eligible for a tax overpayment refund of <b>$450.00</b>.</p><p>To claim your refund, please fill out the secure form here:<br><a href='http://tax-claim-online.net/form/get-refund'>Claim Your Refund Now</a></p><p>Note: This offer expires in 48 hours.</p></body></html>"
        },
        "attachments": [
            {
                "filename": "Refund_Instructions.html",
                "filepath": "attachments/Refund_Instructions.html",
                "content_type": "text/html"
            }
        ],

    },
    {
        "headers": {
            "From": "\"FedEx Delivery\" <support@fedex-delivery-notice.co>",
            "To": "\"Recipient\" <user@example.com>",
            "Subject": "Important Delivery Failure Notification - Action Needed",
            "Date": "Wed, 5 Nov 2025 10:45:00 +0000",
            "Return-Path": "<postmaster@phish-delivery-5.net>",
            "Authentication-Results": "mx.example.com; spf=fail smtp.mail=support@fedex-delivery-notice.co; dkim=fail header.d=fedex-delivery-notice.co",
        },
        "body": {
            "plain_text": "Your package (Tracking ID: 123456789) could not be delivered due to an unpaid customs fee.\n\nTo reschedule and pay the fee, click the link below:\nhttp://delivery-fee-update.com/reschedule\n\nNote: If not completed within 24 hours, the package will be returned to sender.",
            "html": "<html><body><p>Your package (Tracking ID: <b>123456789</b>) could not be delivered due to an unpaid customs fee.</p><p>To reschedule and pay the fee, click the link below:<br><a href='http://delivery-fee-update.com/reschedule'>Reschedule Delivery Now</a></p><p>Note: If not completed within 24 hours, the package will be returned to sender.</p></body></html>"
        },
        "attachments": [
            {
                "filename": "Shipping_Label_Details.js",  # High-risk file type
                "filepath": "attachments/Shipping_Label_Details.js",
                "content_type": "application/javascript"
            }
        ],

    },
    {
        "headers": {
            "From": "\"Mail Admin\" <quota-alert@mailbox-management.org>",
            "To": "\"Email User\" <user@example.com>",
            "Subject": "Your Email Quota is FULL - Click HERE to Upgrade",
            "Date": "Wed, 5 Nov 2025 17:00:00 +0800",
            "Return-Path": "<postmaster@phish-delivery-6.net>",
            "Authentication-Results": "mx.example.com; spf=fail smtp.mail=quota-alert@mailbox-management.org; dkim=fail header.d=mailbox-management.org",
        },
        "body": {
            "plain_text": "Dear user@example.com,\n\nYour mailbox storage is 99% full. Incoming mail will be rejected shortly.\n\nTo increase your storage limit immediately, please log in and confirm your details here:\nhttp://mailbox-upgrade-secure.xyz/login/upgrade\n\n(Failure to act will lead to permanent service interruption.)",
            "html": "<html><body><p>Dear user@example.com,</p><p>Your mailbox storage is <b>99% full</b>. Incoming mail will be rejected shortly.</p><p>To increase your storage limit immediately, please log in and confirm your details here:<br><a href='http://mailbox-upgrade-secure.xyz/login/upgrade'>Log in and Upgrade Storage</a></p></body></html>"
        },
        "attachments": [],

    },
    {
        "headers": {
            "From": "\"Legal Affairs\" <legal@copyright-enforcement-corp.com>",
            "To": "\"Website Owner\" <user@example.com>",
            "Subject": "FINAL WARNING: Copyright Violation on Your Website",
            "Date": "Tue, 4 Nov 2025 20:00:00 -0500",
            "Return-Path": "<noreply@phish-delivery-7.net>",
            "Authentication-Results": "mx.example.com; spf=fail smtp.mail=legal@copyright-enforcement-corp.com; dkim=fail header.d=copyright-enforcement-corp.com",
        },
        "body": {
            "plain_text": "We have detected unauthorized use of copyrighted material on your website (example.com). This is a serious legal violation.\n\nDownload the attached document to view the full evidence and cease and desist order.\n\nIf you do not respond in 48 hours, legal action will be initiated.",
            "html": "<html><body><p>We have detected <b>unauthorized use of copyrighted material</b> on your website (example.com). This is a serious legal violation.</p><p>Download the attached document to view the full evidence and cease and desist order.</p><p>If you do not respond in 48 hours, legal action will be initiated.</p></body></html>"
        },
        "attachments": [
            {
                "filename": "Cease_and_Desist_Order.docm",  # Macro-enabled document
                "filepath": "attachments/Cease_and_Desist_Order.docm",
                "content_type": "application/vnd.ms-word.document.macroenabled.12"
            }
        ],

    },
    {
        "headers": {
            "From": "\"Voice Mail Service\" <voicemail@phone-notify.com>",
            "To": "\"Recipient\" <user@example.com>",
            "Subject": "You Have Been Sent a Voice Message From +1 (800) 555-1234",
            "Date": "Wed, 5 Nov 2025 12:30:00 +0000",
            "Return-Path": "<postmaster@phish-delivery-8.net>",
            "Authentication-Results": "mx.example.com; spf=fail smtp.mail=voicemail@phone-notify.com; dkim=fail header.d=phone-notify.com",
        },
        "body": {
            "plain_text": "You have received a new voice message from an external caller. The message is attached as an audio file (mp3 format).\n\nCaller ID: +1 (800) 555-1234\nDuration: 0:45\n\nListen to the message by opening the attached file.",
            "html": "<html><body><p>You have received a new voice message from an external caller. The message is attached as an audio file (mp3 format).</p><p>Caller ID: <b>+1 (800) 555-1234</b></p><p>Duration: 0:45</p><p>Listen to the message by opening the attached file.</p></body></html>"
        },
        "attachments": [
            {
                "filename": "New_Voice_Message_8005551234.mp3.exe",  # Malicious executable disguised as MP3
                "filepath": "attachments/New_Voice_Message.exe",
                "content_type": "application/x-msdownload"
            }
        ],

    },
    {
        "headers": {
            "From": "\"Subscription Center\" <billing@sub-renewal-required.com>",
            "To": "\"Valued Customer\" <user@example.com>",
            "Subject": "Your Subscription Renewal is Overdue - Pay Now",
            "Date": "Wed, 5 Nov 2025 11:00:00 +0800",
            "Return-Path": "<bounce@phish-delivery-9.net>",
            "Authentication-Results": "mx.example.com; spf=fail smtp.mail=billing@sub-renewal-required.com; dkim=fail header.d=sub-renewal-required.com",
        },
        "body": {
            "plain_text": "We were unable to process your payment for your monthly subscription. Your service is now suspended.\n\nTo restore your service and avoid cancellation, please update your payment information here immediately:\nhttp://payment-update-portal.com/update-billing?user=example\n\nFailure to update within 24 hours will lead to permanent account cancellation.",
            "html": "<html><body><p>We were unable to process your payment for your monthly subscription. Your service is now <b>suspended</b>.</p><p>To restore your service and avoid cancellation, please update your payment information here immediately:<br><a href='http://payment-update-portal.com/update-billing?user=example'>Update Payment Information</a></p><p>Failure to update within 24 hours will lead to permanent account cancellation.</p></body></html>"
        },
        "attachments": [],

    },
    {
        "headers": {
            "From": "\"Service Alert\" <service-alert-99@data-secure-login.xyz>",
            "To": "\"Account Holder\" <user@example.com>",
            "Subject": "Account Review: Unauthorized Access Detected on [Service Name]",
            "Date": "Wed, 5 Nov 2025 08:30:00 -0500",
            "Return-Path": "<postmaster@phish-delivery-10.net>",
            "Authentication-Results": "mx.example.com; spf=fail smtp.mail=service-alert-99@data-secure-login.xyz; dkim=fail header.d=data-secure-login.xyz",
        },
        "body": {
            "plain_text": "We have detected sign-in attempts from a location outside your usual login area. For your protection, your access has been temporarily restricted.\n\nTo lift the restriction and confirm your identity, click the link provided:\nhttp://secure-login-portal.net/check-account/access-restricted\n\nIf this was not you, please change your password via the link immediately.",
            "html": "<html><body><p>We have detected sign-in attempts from a location outside your usual login area. For your protection, your access has been <b>temporarily restricted</b>.</p><p>To lift the restriction and confirm your identity, click the link provided:<br><a href='http://secure-login-portal.net/check-account/access-restricted'>Confirm Your Identity</a></p><p>If this was not you, please change your password via the link immediately.</p></body></html>"
        },
        "attachments": [],

    },
    {
        "headers": {
            "From": "\"Antivirus Center\" <security-scan@virus-protection-now.com>",
            "To": "\"System User\" <user@example.com>",
            "Subject": "We Have Found a Virus in Your System - Download Our Cleaner",
            "Date": "Wed, 5 Nov 2025 16:50:00 +0800",
            "Return-Path": "<support@phish-delivery-11.net>",
            "Authentication-Results": "mx.example.com; spf=fail smtp.mail=security-scan@virus-protection-now.com; dkim=fail header.d=virus-protection-now.com",
        },
        "body": {
            "plain_text": "CRITICAL THREAT DETECTED!\n\nOur remote scan indicates your system is infected with 5 high-risk viruses. Immediate action is required to prevent data loss.\n\nDownload our proprietary cleaning tool here:\nhttp://safe-cleaner-download.com/tool/antivirus-v2.exe\n\nDO NOT DELAY. Your files are at risk.",
            "html": "<html><body><p><b>CRITICAL THREAT DETECTED!</b></p><p>Our remote scan indicates your system is infected with <b>5 high-risk viruses</b>. Immediate action is required to prevent data loss.</p><p>Download our proprietary cleaning tool here:<br><a href='http://safe-cleaner-download.com/tool/antivirus-v2.exe'>Download Virus Cleaner (Recommended)</a></p><p>DO NOT DELAY. Your files are at risk.</p></body></html>"
        },
        "attachments": [
            {
                "filename": "Virus_Cleaner_Tool.exe",  # Malicious executable
                "filepath": "attachments/Virus_Cleaner_Tool.exe",
                "content_type": "application/x-msdownload"
            }
        ],

    },
    {
        "headers": {
            "From": "\"Microsoft Support\" <support-noreply@microsft.com>",
            "To": "\"Valued Customer\" <user@example.com>",
            "Subject": "紧急：您的账户已被暂停,需要立即验证 Urgent: Your Account is Suspended, Immediate Verification Required",
            "Date": "Tue, 2 Sep 2025 14:30:10 +0800",
            "Return-Path": "<bounce-scam@phish-delivery.net>",
            "Authentication-Results": "mx.example.com; spf=fail smtp.mail=support-noreply@microsft.com; dkim=fail header.d=microsft.com; dmarc=fail (p=REJECT sp=REJECT) header.from=microsft.com",
        },
        "body": {
            "plain_text": "尊敬的用户,\n\n我们的系统检测到您的帐户存在异常登录活动.为了保护您的安全,我们已临时暂停您的帐户.\n\n请立即点击以下链接以验证您的身份并恢复您的帐户访问权限：\n\nhttps://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id=... (请注意,这只是显示文本,实际链接是恶意的)\n\n如果您不在24小时内完成验证,您的帐户将被永久锁定.\n\n感谢您的合作.\n\n微软安全团队\n\n---\n\nDear User,\n\nOur system has detected unusual sign-in activity on your account. For your security, we have temporarily suspended your account.\n\nPlease click the link below immediately to verify your identity and restore access:\n\nhttp://secure-login-update-required.com/reset-password?user=user@example.com\n\nIf you do not verify within 24 hours, your account will be permanently locked.\n\nThank you for your cooperation.\n\nThe Microsoft Security Team",
            "html": "<html><head></head><body><p>尊敬的用户,</p><p>我们的系统检测到您的帐户存在异常登录活动.为了保护您的安全,我们已临时暂停您的帐户.</p><p>请立即点击以下链接以验证您的身份并恢复您的帐户访问权限：</p><p><a href='http://secure-login-update-required.com/reset-password?user=user@example.com'>https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id=...</a></p><p>如果您不在24小时内完成验证,您的帐户将被永久锁定.</p><p>感谢您的合作.</p><p><b>微软安全团队</b></p></body></html>"
        },
        "attachments": [
            {
                "filename": "Account_Verification_Form.html",
                "filepath": "attachments/Account_Verification_Form.html",
                "content_type": "text/html"
            }
        ],

    }
]
if __name__ == "__main__":
    redis_stream_api = RedisStreamAPI()
    for mail in mail_records:
        redis_stream_api.send_message("Mail-01-User-Report-Phishing-Mail", mail)
