import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import random
import time
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
SENDER_EMAIL = "EMAIL HERE"          # Put your real email here
SENDER_PASSWORD = "PASS HERE"
class EmailService:
    def __init__(self):
        # We will load these from your config or hardcode for testing
        self.smtp_server = "smtp.gmail.com"
        self.smtp_port = 587
        
        # TODO: Replace with your Gmail and the 16-letter App Password you generated
        self.sender_email = "EMAILHERE" 
        self.sender_password = "PASS HERE" 
        
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


def send_security_alert(target_email, event_type, message, filepath=None):
    """
    Sends a formatted HTML security alert email to the Administrator.
    """
    if not target_email:
        return False, "No target email provided."

    subject = f"🚨 SECURITY ALERT: {event_type} Detected!"
    
    # Create a professional HTML email template
    html_content = f"""
    <html>
    <body style="font-family: Arial, sans-serif; background-color: #f4f4f4; padding: 20px;">
        <div style="max-width: 600px; margin: 0 auto; background-color: #ffffff; padding: 30px; border-radius: 8px; border-top: 5px solid #ef4444; box-shadow: 0 4px 8px rgba(0,0,0,0.1);">
            <h2 style="color: #ef4444; margin-top: 0;">⚠️ FMSecure Alert</h2>
            <p style="font-size: 16px; color: #333333;">The File Integrity Monitor has detected a high-priority security event on your system.</p>
            
            <table style="width: 100%; border-collapse: collapse; margin-top: 20px;">
                <tr style="background-color: #f8fafc;">
                    <td style="padding: 10px; border: 1px solid #e2e8f0; font-weight: bold; width: 120px;">Event Type:</td>
                    <td style="padding: 10px; border: 1px solid #e2e8f0; color: #ef4444; font-weight: bold;">{event_type}</td>
                </tr>
                <tr>
                    <td style="padding: 10px; border: 1px solid #e2e8f0; font-weight: bold;">Details:</td>
                    <td style="padding: 10px; border: 1px solid #e2e8f0;">{message}</td>
                </tr>
    """
    
    if filepath:
        html_content += f"""
                <tr style="background-color: #f8fafc;">
                    <td style="padding: 10px; border: 1px solid #e2e8f0; font-weight: bold;">Target Path:</td>
                    <td style="padding: 10px; border: 1px solid #e2e8f0; font-family: monospace;">{filepath}</td>
                </tr>
        """
        
    html_content += f"""
            </table>
            
            <p style="margin-top: 30px; font-size: 12px; color: #666666; border-top: 1px solid #eeeeee; padding-top: 10px;">
                Generated automatically by Secure File Integrity Monitor v2.0<br>
                Please check your server immediately.
            </p>
        </div>
    </body>
    </html>
    """

    try:
        # Create message container
        msg = MIMEMultipart('alternative')
        msg['Subject'] = subject
        msg['From'] = SENDER_EMAIL
        msg['To'] = target_email

        # Attach HTML
        part = MIMEText(html_content, 'html')
        msg.attach(part)

        # Connect to server and send
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(SENDER_EMAIL, SENDER_PASSWORD)
        server.send_message(msg)
        server.quit()
        
        return True, "Alert email sent successfully."
    except Exception as e:
        return False, f"Failed to send alert email: {str(e)}"