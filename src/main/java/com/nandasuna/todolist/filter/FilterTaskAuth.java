package com.nandasuna.todolist.filter;

import java.io.IOException;
import java.util.Base64;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.nandasuna.todolist.user.IUserRepository;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import at.favre.lib.crypto.bcrypt.BCrypt;

@Component
public class FilterTaskAuth extends OncePerRequestFilter {

    @Autowired
    private IUserRepository userRepository;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

                var serveletPath = request.getServletPath();

                if(serveletPath.startsWith("/tasks/")) {
                    //pegar autenticação (user password)
                    var authorization = request.getHeader("Authorization");
                    
                    var authEncoded = authorization.substring("Basic".length()).trim();
                    byte[] authDecode = Base64.getDecoder().decode(authEncoded);
                    var authString = new String(authDecode);
                    String[] credentials = authString.split(":");
                    var username = credentials[0];
                    var password = credentials[1];

                    // validar usuario
                    var user = this.userRepository.findByUsername(username);
                    if (user == null) {
                        response.sendError(401);
                    } else {
                        // validar senha
                        var passwordVerify = BCrypt.verifyer().verify(password.toCharArray(),user.getPassword());
                        if(passwordVerify.verified) {
                            // seguir viagem
                            request.setAttribute("idUser", user.getId());
                            filterChain.doFilter(request, response);
                        } else {
                            response.sendError(401);
                        }

                    }
                } else {
                    filterChain.doFilter(request, response);
                }

    }

    
}
