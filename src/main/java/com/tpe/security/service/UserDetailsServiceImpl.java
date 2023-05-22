package com.tpe.security.service;


import com.tpe.domain.User;
import com.tpe.exception.ResourceNotFoundException;
import com.tpe.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class UserDetailsServiceImpl implements UserDetailsService {
    @Autowired
    private UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        //we are getting user entity from database
        User user = userRepository.findByUserName(username).orElseThrow(
                ()->new ResourceNotFoundException("User with username : "+username+" not found")
        );
        return UserDetailsImpl.build(user);
    }
}
