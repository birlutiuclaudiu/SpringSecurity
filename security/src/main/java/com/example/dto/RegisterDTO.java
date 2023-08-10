package com.example.dto;

import com.example.model.UserRole;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

@AllArgsConstructor
@NoArgsConstructor
@Getter
public class RegisterDTO {

    private String email;
    private String password;
    private UserRole userRole;
}
