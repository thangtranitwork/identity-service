package com.thangtranit.identityservice.service;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.mail.javamail.MimeMessagePreparator;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.thymeleaf.TemplateEngine;
import org.thymeleaf.context.Context;

import java.util.Map;

@Service
@RequiredArgsConstructor
public class EmailService {

    @Value("${spring.mail.username}")
    private String FROM_EMAIL;
    private final JavaMailSender javaMailSender;
    private final TemplateEngine templateEngine;

    @Async
    public void sendMail(String toEmail, String subject, Map<String, Object> variables, String template) {
        MimeMessagePreparator preparator = mimeMessage -> {
            MimeMessageHelper messageHelper = new MimeMessageHelper(mimeMessage, true, "UTF-8");
            messageHelper.setFrom(FROM_EMAIL);
            messageHelper.setSubject(subject);
            messageHelper.setTo(toEmail);

            messageHelper.setText(generateBody(variables, template), true);
        };

        javaMailSender.send(preparator);
        System.out.println("Send a email");
    }

    public String generateBody(Map<String, Object> variables, String template){
        Context context = new Context();
        for (Map.Entry<String, Object> entry : variables.entrySet()){
            context.setVariable(entry.getKey(), entry.getValue());
        }
        return templateEngine.process(template, context);

    }
}
