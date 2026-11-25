package com.iam.service;

import jakarta.mail.internet.MimeMessage;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
@Slf4j
public class EmailService {

    private final JavaMailSender mailSender;

    @Value("${spring.mail.username:hohoanluong2000k1@gmail.com}")
    private String fromEmail;

    public void sendOtpEmail(String toEmail, String otpCode, String subject, String actionTitle, String actionDesc) {
        try {
            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");

            helper.setFrom(fromEmail, "IAM System Security");
            helper.setTo(toEmail);
            helper.setSubject(subject);

            String htmlContent = """
                <!DOCTYPE html>
                <html>
                <head>
                    <meta charset="UTF-8">
                    <style>
                        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #0b0a1a; color: #e2e8f0; margin: 0; padding: 20px; }
                        .container { max-width: 540px; margin: 0 auto; background: #13122c; border: 1px solid #7c3aed; border-radius: 16px; padding: 32px; box-shadow: 0 10px 30px rgba(124, 58, 237, 0.2); }
                        .header { text-align: center; margin-bottom: 24px; }
                        .title { font-size: 22px; font-weight: 700; color: #c084fc; margin-bottom: 8px; }
                        .desc { font-size: 14px; color: #94a3b8; line-height: 1.6; }
                        .otp-box { text-align: center; margin: 30px 0; background: linear-gradient(135deg, rgba(124, 58, 237, 0.2), rgba(236, 72, 153, 0.2)); border: 1px dashed #ec4899; border-radius: 12px; padding: 20px; }
                        .otp-code { font-size: 36px; font-weight: 800; letter-spacing: 8px; color: #f43f5e; font-family: 'Courier New', monospace; }
                        .warning { font-size: 12px; color: #cbd5e1; text-align: center; margin-top: 16px; }
                        .footer { text-align: center; margin-top: 28px; font-size: 11px; color: #64748b; border-top: 1px solid #23224d; padding-top: 16px; }
                    </style>
                </head>
                <body>
                    <div class="container">
                        <div class="header">
                            <div class="title">%s ✨</div>
                            <div class="desc">%s</div>
                        </div>
                        <div class="otp-box">
                            <div style="font-size: 13px; color: #cbd5e1; margin-bottom: 8px;">MÃ XÁC THỰC BẢO MẬT (OTP)</div>
                            <div class="otp-code">%s</div>
                        </div>
                        <div class="warning">
                            Mã xác thực có hiệu lực trong vòng <strong>5 phút</strong>.<br>
                            Vì lý do an toàn bảo mật, tuyệt đối <strong>không chia sẻ</strong> mã này với bất kỳ ai!
                        </div>
                        <div class="footer">
                            Đây là email tự động từ hệ thống Identity & Access Management (IAM Verse).<br>
                            Nếu bạn không yêu cầu hành động này, vui lòng bỏ qua email.
                        </div>
                    </div>
                </body>
                </html>
                """.formatted(actionTitle, actionDesc, otpCode);

            helper.setText(htmlContent, true);
            mailSender.send(message);
            log.info("Sent OTP email successfully to {}", toEmail);
        } catch (Exception e) {
            log.error("Failed to send email to {}: {}", toEmail, e.getMessage(), e);
            throw new RuntimeException("Gửi email thất bại: " + e.getMessage(), e);
        }
    }
}
