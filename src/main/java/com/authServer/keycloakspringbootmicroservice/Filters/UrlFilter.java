package com.authServer.keycloakspringbootmicroservice.Filters;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

@Component
public class UrlFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        String origin = request.getHeader("Origin");
        if (origin == null || !origin.contains("http://localhost:4200")) {
            response.sendError(HttpStatus.SC_BAD_REQUEST, "Forbidden Access");
            return;
        }
        filterChain.doFilter(request, response);

    }

}
