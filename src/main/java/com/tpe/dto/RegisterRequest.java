package com.tpe.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.Size;
import java.util.Set;
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class RegisterRequest {
    @NotBlank(message = "Please enter firstname")
    private String firstName;

    @NotBlank(message = "Please enter lastname")
    private String lastName;

    @NotBlank(message = "Please enter username")
    @Size(min = 2,max = 20,message = "Username should have characters between {min} and {max}")
    private  String userName;

    @NotBlank(message = "Please enter password")
    private String password;

    private Set<String> roles;

}
