package com.yaroslav.security.auth;


import lombok.*;
import lombok.experimental.FieldDefaults;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE)
public class RegisterRequest {

    String firstname;

    String lastname;

    String email;

    String password;
}
