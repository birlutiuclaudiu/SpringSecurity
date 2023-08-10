package com.example.service;

import com.example.dto.CredentialsDTO;
import com.example.dto.RegisterDTO;
import com.example.model.User;
import com.example.repository.UserRepository;
import com.example.security.TokenProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class UserService {

    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;
    private final TokenProvider tokenProvider;
    private final UserDetailsService userDetailsService;

    @Autowired
    public UserService(AuthenticationManager authenticationManager, UserRepository userRepository, TokenProvider tokenProvider, BCryptPasswordEncoder bCryptPasswordEncoder, TokenProvider tokenProvider1, UserDetailsService userDetailsService) {
        this.authenticationManager = authenticationManager;
        this.userRepository = userRepository;
        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
        this.tokenProvider = tokenProvider1;
        this.userDetailsService = userDetailsService;
    }


    public String authenticate(CredentialsDTO credentialsDTO) throws Exception {
        try {
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(credentialsDTO.getEmail(), credentialsDTO.getPassword()));
            return tokenProvider.provideToken((User) userDetailsService.loadUserByUsername(credentialsDTO.getEmail()));
        } catch (DisabledException e) {
            throw new Exception("USER_DISABLED", e);
        } catch (BadCredentialsException e) {
            throw new Exception("INVALID_CREDENTIALS", e);
        }
    }


    public void registerUser(RegisterDTO registerDTO) {
        User user = User.builder()
                .email(registerDTO.getEmail())
                .password(bCryptPasswordEncoder.encode(registerDTO.getPassword()))
                .role(registerDTO.getUserRole())
                .build();
        userRepository.save(user);
    }
}
