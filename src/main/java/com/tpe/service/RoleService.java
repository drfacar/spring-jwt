package com.tpe.service;

import com.tpe.domain.Role;
import com.tpe.domain.enums.UserRole;
import com.tpe.exception.ResourceNotFoundException;
import com.tpe.repository.RoleRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class RoleService {

    @Autowired
    private RoleRepository repository;

    public Role findByName(UserRole roleType) {
        Role role = repository.findByName(roleType).orElseThrow(
                ()->new ResourceNotFoundException("Role not found in DB")
        );
        return role;
    }
}
