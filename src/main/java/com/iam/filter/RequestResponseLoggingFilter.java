package com.iam.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.ContentCachingRequestWrapper;
import org.springframework.web.util.ContentCachingResponseWrapper;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.regex.Pattern;

/**
 * Filter ghi log request, response theo yêu cầu đề bài mục 8:
 * - Ghi log request URL, Method, status code, thời gian xử lý
 * - Che giấu hoàn toàn các thông tin nhạy cảm (password, secret, token)
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
@Slf4j
public class RequestResponseLoggingFilter extends OncePerRequestFilter {

    private static final Pattern SENSITIVE_DATA_PATTERN = Pattern.compile(
            "\"(password|oldPassword|newPassword|clientSecret|client_secret|refreshToken|refresh_token)\"\\s*:\\s*\"[^\"]*\"",
            Pattern.CASE_INSENSITIVE
    );

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        // Không log các file tĩnh và swagger docs để tránh spam log
        String uri = request.getRequestURI();
        if (uri.startsWith("/v3/api-docs") || uri.startsWith("/swagger-ui") || uri.endsWith(".css") || uri.endsWith(".js") || uri.endsWith(".ico")) {
            filterChain.doFilter(request, response);
            return;
        }

        long startTime = System.currentTimeMillis();
        ContentCachingRequestWrapper requestWrapper = new ContentCachingRequestWrapper(request, 1024 * 1024);
        ContentCachingResponseWrapper responseWrapper = new ContentCachingResponseWrapper(response);

        try {
            filterChain.doFilter(requestWrapper, responseWrapper);
        } finally {
            long duration = System.currentTimeMillis() - startTime;
            logRequestAndResponse(requestWrapper, responseWrapper, duration);
            responseWrapper.copyBodyToResponse();
        }
    }

    private void logRequestAndResponse(ContentCachingRequestWrapper request, ContentCachingResponseWrapper response, long duration) {
        String method = request.getMethod();
        String uri = request.getRequestURI();
        String queryString = request.getQueryString() != null ? "?" + request.getQueryString() : "";
        int status = response.getStatus();

        String requestBody = getPayload(request.getContentAsByteArray());
        String responseBody = getPayload(response.getContentAsByteArray());

        // Mask thông tin nhạy cảm
        String maskedRequestBody = maskSensitiveData(requestBody);
        String maskedResponseBody = maskSensitiveData(responseBody);

        log.info("[HTTP] {} {}{} | Status={} | Duration={}ms | ReqBody={} | RespBody={}",
                method, uri, queryString, status, duration,
                maskedRequestBody.isBlank() ? "-" : maskedRequestBody,
                maskedResponseBody.isBlank() ? "-" : (maskedResponseBody.length() > 500 ? maskedResponseBody.substring(0, 500) + "...(truncated)" : maskedResponseBody)
        );
    }

    private String getPayload(byte[] content) {
        if (content == null || content.length == 0) {
            return "";
        }
        return new String(content, StandardCharsets.UTF_8).replaceAll("[\\r\\n]+", " ").trim();
    }

    private String maskSensitiveData(String content) {
        if (content == null || content.isBlank()) {
            return "";
        }
        return SENSITIVE_DATA_PATTERN.matcher(content).replaceAll("\"$1\":\"***MASKED***\"");
    }
}
