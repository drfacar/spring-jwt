package com.tpe.domain;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import javax.persistence.*;
import java.util.HashSet;
import java.util.Set;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor

@Entity
@Table(name = "tbl_user")
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(length = 25,nullable = false)
    private String firstName;
    @Column(length = 25,nullable = false)
    private String lastName;

    @Column(length = 25,nullable = false,unique = true)
    private  String userName;

    @Column(length = 255,nullable = false)//2 --> base64
    private String password;

//!!!Note Step 1
    @ManyToMany(fetch = FetchType.EAGER) //by default fetch type is Lazy. If we want to see user's role
    // directly we need to set fetch to Eager
    @JoinTable(name = "tbl_user_role",
            joinColumns = @JoinColumn(name="user_id"),
            inverseJoinColumns = @JoinColumn(name="role_id"))
    private Set<Role> roles = new HashSet<>();



}
