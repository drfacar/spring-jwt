package com.tpe.service;


import com.tpe.domain.Role;
import com.tpe.domain.User;
import com.tpe.domain.enums.UserRole;
import com.tpe.dto.RegisterRequest;
import com.tpe.exception.ConflictException;
import com.tpe.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.HashSet;
import java.util.Set;

@Service
public class UserService {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private RoleService roleService;

    public void registerUser(RegisterRequest request) {
        if(userRepository.existsByUserName(request.getUserName())){
            throw new ConflictException("Username is already in use");
        }
        //getting role from database
        //setting default role to registered user
        //default role of user will be "Student"
        Role role = roleService.findByName(UserRole.ROLE_STUDENT);
        Set<Role> roles = new HashSet<>();
        roles.add(role);

        //map dto(RegisteredRequest) to User entity
        User newUser = new User();
        newUser.setFirstName(request.getFirstName());
        newUser.setLastName(request.getLastName());
        newUser.setUserName(request.getUserName());
        newUser.setRoles(roles);
        newUser.setPassword(passwordEncoder.encode(request.getPassword()));

        //persist data
        userRepository.save(newUser);

    }
}
