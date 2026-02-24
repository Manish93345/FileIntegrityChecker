import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import random
import time

class EmailService:
    def __init__(self):
        # We will load these from your config or hardcode for testing
        self.smtp_server = "smtp.gmail.com"
        self.smtp_port = 587
        
        # TODO: Replace with your Gmail and the 16-letter App Password you generated
        self.sender_email = "glimpsefilmy@gmail.com" 
        self.sender_password = "bocwoewklavlnzkt" 
        
        # Memory to store OTPs temporarily (Email -> {otp, timestamp})
        self.active_otps = {}

    def generate_otp(self):
        """Generate a secure 6-digit OTP"""
        return str(random.randint(100000, 999999))

    def send_otp_email(self, recipient_email, purpose="verification"):
        """Send an HTML-formatted OTP email"""
        otp = self.generate_otp()
        
        # Store OTP with a 5-minute expiration timestamp
        self.active_otps[recipient_email.lower()] = {
            "otp": otp,
            "expires": time.time() + 300 # 5 minutes
        }

        # Subject logic
        if purpose == "reset":
            subject = "FMSecure - Password Reset Code"
            action = "reset your password"
        else:
            subject = "FMSecure - Verify Your Email"
            action = "complete your registration"

        # Beautiful HTML Email Template
        html_content = f"""
        <html>
            <body style="font-family: Arial, sans-serif; background-color: #f4f4f4; padding: 20px;">
                <div style="max-width: 500px; margin: 0 auto; background-color: #ffffff; padding: 30px; border-radius: 8px; border-top: 4px solid #00a8ff;">
                    <h2 style="color: #333333; margin-top: 0;">🛡️ FMSecure Security</h2>
                    <p style="color: #555555; font-size: 16px;">You requested to {action}. Please use the following One-Time Password (OTP):</p>
                    <div style="background-color: #f8f9fa; padding: 15px; text-align: center; border-radius: 4px; margin: 25px 0;">
                        <span style="font-size: 32px; font-weight: bold; color: #00a8ff; letter-spacing: 5px;">{otp}</span>
                    </div>
                    <p style="color: #888888; font-size: 14px;">This code will expire in 5 minutes. If you did not request this, please ignore this email.</p>
                </div>
            </body>
        </html>
        """

        # Construct the email
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = f"FMSecure Monitor <{self.sender_email}>"
        msg["To"] = recipient_email
        msg.attach(MIMEText(html_content, "html"))

        # Send the email
        try:
            server = smtplib.SMTP(self.smtp_server, self.smtp_port)
            server.starttls() # Secure the connection
            server.login(self.sender_email, self.sender_password)
            server.send_message(msg)
            server.quit()
            return True, "OTP sent successfully!"
        except Exception as e:
            return False, f"Failed to send email: {e}"

    def verify_otp(self, email, submitted_otp):
        """Check if the OTP is correct and not expired"""
        email_key = email.lower()
        if email_key not in self.active_otps:
            return False, "No OTP requested for this email."
            
        record = self.active_otps[email_key]
        
        # Check expiration
        if time.time() > record["expires"]:
            del self.active_otps[email_key]
            return False, "OTP has expired. Please request a new one."
            
        # Check match
        if record["otp"] == submitted_otp.strip():
            del self.active_otps[email_key] # Burn it after use
            return True, "Email verified successfully!"
            
        return False, "Incorrect OTP."

# Global instance
email_service = EmailService()